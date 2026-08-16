/*
 * SPDX-FileCopyrightText: 2026 The tethermesh Authors
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * sniffer.c — a receive-only SX1262 driver that dumps RAW LoRa frames.
 *
 * WHY THIS EXISTS
 * ---------------
 * meshtastic/WIRE_REFERENCE.md items 1 and 2 — the 16-byte header layout and
 * the AES-CTR nonce construction — are the last things blocking the frame
 * codec, and neither is obtainable from any local boundary. The reference
 * implementation's simulated radio hands the packed frame to a PHY inside its
 * own process; UDP-over-mesh carries a protobuf MeshPacket rather than the
 * frame; the phone API carries the same. The packed bytes exist only between
 * a real modem and the air.
 *
 * So: a radio we drive ourselves, listening to what a stock node transmits,
 * printing the buffer verbatim. Nothing here interprets the bytes — that is
 * deliberate, because interpreting them is the job of the codec this is meant
 * to inform, and a sniffer that already knows the layout cannot discover it.
 *
 * NOT RADIOLIB, AND THAT IS A HARD CONSTRAINT
 * -------------------------------------------
 * RadioLib is GPL-3.0. tethermesh's README forbids linking it and
 * tools/check_cleanroom.sh fails on any file that mentions it. This driver is
 * written from the SX126x datasheet's documented command set — opcodes,
 * register addresses and parameter encodings are facts about the part, the
 * same category as field numbers on a wire.
 *
 * PARAMETERS, AND WHERE EACH ONE CAME FROM
 * ----------------------------------------
 *   frequency 906.875 MHz   observed: the node reports it for US/LongFast
 *   SF 11, BW 250 kHz, CR 4/5
 *                           MEASURED this session by writing a LoRaConfig with
 *                           use_preset=true and those fields absent, then
 *                           reading back what the firmware filled in
 *   preamble 16 symbols     derived: reported preamble time 131 ms divided by
 *                           the SF11/BW250 symbol time of 8.192 ms is 15.99
 *   LDRO off                derived: required only above 16.38 ms symbol time
 *   sync word 0x24 0xB4     THE ONE GUESS. WIRE_REFERENCE item 5 records that
 *                           the commonly quoted 0x2B is a library-level value
 *                           expanded by a driver into a register pair, and
 *                           that the on-air value was never pinned. This is
 *                           that expansion. If no frames arrive, this is the
 *                           first thing to sweep — and a successful decode is
 *                           what turns item 5 from asserted into verified.
 *
 * Heltec V3 wiring is from Heltec's published board documentation, not from
 * any Meshtastic source. If SPI answers and the part reports a sane status,
 * the pinout is right; that check runs at boot and says so.
 */
#include <stdio.h>
#include <string.h>
#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "driver/uart.h"
#include "driver/uart_vfs.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "sniff";

/* ── Heltec WiFi LoRa 32 V3 ─────────────────────────────────────────────── */
#define PIN_NSS   8
#define PIN_SCK   9
#define PIN_MOSI  10
#define PIN_MISO  11
#define PIN_RST   12
#define PIN_BUSY  13
#define PIN_DIO1  14

/* ── SX126x opcodes ─────────────────────────────────────────────────────── */
#define CMD_SET_TX                 0x83
#define CMD_WRITE_BUFFER           0x0E
#define CMD_SET_PA_CONFIG          0x95
#define CMD_SET_TX_PARAMS          0x8E
#define CMD_SET_STANDBY            0x80
#define CMD_SET_RX                 0x82
#define CMD_SET_RF_FREQUENCY       0x86
#define CMD_SET_PACKET_TYPE        0x8A
#define CMD_SET_MODULATION_PARAMS  0x8B
#define CMD_SET_PACKET_PARAMS      0x8C
#define CMD_SET_BUFFER_BASE_ADDR   0x8F
#define CMD_SET_DIO_IRQ_PARAMS     0x08
#define CMD_GET_IRQ_STATUS         0x12
#define CMD_CLR_IRQ_STATUS         0x02
#define CMD_GET_RX_BUFFER_STATUS   0x13
#define CMD_GET_PACKET_STATUS      0x14
#define CMD_READ_BUFFER            0x1E
#define CMD_WRITE_REGISTER         0x0D
#define CMD_READ_REGISTER          0x1D
#define CMD_GET_STATUS             0xC0
#define CMD_GET_DEVICE_ERRORS      0x17
#define CMD_SET_DIO2_AS_RFSWITCH   0x9D
#define CMD_SET_DIO3_AS_TCXO       0x97
#define CMD_SET_REGULATOR_MODE     0x96
#define CMD_CALIBRATE              0x89

#define REG_LORA_SYNC_WORD_MSB     0x0740
#define REG_LORA_SYNC_WORD_LSB     0x0741

#define IRQ_RX_DONE   (1u << 1)
#define IRQ_CRC_ERR   (1u << 6)
#define IRQ_TIMEOUT   (1u << 9)
#define IRQ_HDR_ERR   (1u << 5)
#define IRQ_TX_DONE   (1u << 0)

static spi_device_handle_t spi;

static void busy_wait(void)
{
    /* Every command must be issued with BUSY low. Bounded rather than a bare
     * spin: a part that never releases BUSY is a wiring or TCXO fault, and
     * hanging here would present as "no frames" — the same symptom as a wrong
     * sync word, which is the one thing that must stay distinguishable. */
    /* BUSY stays high for the whole of a transmission — roughly 800 ms at
     * SF11 — so this is not a short wait and must not be a spin. A short
     * micro-delay covers the common case (a command completing in
     * microseconds) without a context switch; anything longer yields to the
     * scheduler so the idle task runs and the watchdog stays quiet. */
    for (int i = 0; i < 200; i++) {
        if (!gpio_get_level(PIN_BUSY)) return;
        esp_rom_delay_us(50);
    }
    for (int i = 0; i < 2000; i++) {
        if (!gpio_get_level(PIN_BUSY)) return;
        vTaskDelay(1);
    }
    ESP_LOGE(TAG, "BUSY stuck high — check wiring / TCXO");
}

static void sx_cmd(uint8_t op, const uint8_t *args, size_t n)
{
    busy_wait();
    uint8_t tx[16];
    tx[0] = op;
    if (n) memcpy(&tx[1], args, n);
    spi_transaction_t t = { .length = 8 * (n + 1), .tx_buffer = tx };
    ESP_ERROR_CHECK(spi_device_polling_transmit(spi, &t));
}

static void sx_read(uint8_t op, uint8_t *out, size_t n)
{
    busy_wait();
    uint8_t tx[32] = {0}, rx[32] = {0};
    tx[0] = op;
    spi_transaction_t t = { .length = 8 * (n + 2), .tx_buffer = tx, .rx_buffer = rx };
    ESP_ERROR_CHECK(spi_device_polling_transmit(spi, &t));
    memcpy(out, &rx[2], n);          /* byte 1 is status, then payload */
}

static void sx_write_reg(uint16_t addr, uint8_t val)
{
    uint8_t a[3] = { (uint8_t)(addr >> 8), (uint8_t)(addr & 0xFF), val };
    sx_cmd(CMD_WRITE_REGISTER, a, 3);
}

static uint8_t sx_read_reg(uint16_t addr)
{
    busy_wait();
    uint8_t tx[5] = { CMD_READ_REGISTER, (uint8_t)(addr >> 8), (uint8_t)(addr & 0xFF), 0, 0 };
    uint8_t rx[5] = {0};
    spi_transaction_t t = { .length = 8 * 5, .tx_buffer = tx, .rx_buffer = rx };
    ESP_ERROR_CHECK(spi_device_polling_transmit(spi, &t));
    return rx[4];
}

static void sx_read_buffer(uint8_t offset, uint8_t *out, uint8_t n)
{
    busy_wait();
    static uint8_t tx[260], rx[260];
    memset(tx, 0, n + 3);
    tx[0] = CMD_READ_BUFFER; tx[1] = offset; tx[2] = 0x00;
    spi_transaction_t t = { .length = 8 * (n + 3), .tx_buffer = tx, .rx_buffer = rx };
    ESP_ERROR_CHECK(spi_device_polling_transmit(spi, &t));
    memcpy(out, &rx[3], n);
}

static void sx_write_buffer(uint8_t offset, const uint8_t *data, uint8_t n)
{
    busy_wait();
    static uint8_t tx[260];
    tx[0] = CMD_WRITE_BUFFER;
    tx[1] = offset;
    memcpy(&tx[2], data, n);
    spi_transaction_t t = { .length = 8 * (n + 2), .tx_buffer = tx };
    ESP_ERROR_CHECK(spi_device_polling_transmit(spi, &t));
}

/* Transmit a frame we constructed ourselves.
 *
 * This is the half of conformance that matters. Reading what a stock node
 * writes only proves our decoder is lenient enough; the question that decides
 * whether anything interoperates is whether THEIR decoder accepts what WE
 * emit. Nothing here interprets the bytes — the host builds the frame, this
 * puts it on the air verbatim, so a rejection is theirs and not an artefact
 * of a helpful modem. */
/* Receive modulation and packet parameters, settable at runtime via MOD.
 *
 * WHY THIS IS RUNTIME
 * -------------------
 * Establishing the coding rate of a preset needs a receiver that can be put
 * DELIBERATELY WRONG and observed failing. In LoRa's explicit-header mode that
 * is impossible: the header carries the payload's coding rate, is itself sent
 * at a fixed 4/8, and the receiver reconfigures from it -- so a mismatched
 * receiver decodes anyway and the configured CR is simply ignored.
 *
 * Implicit-header mode is the discriminator. There the receiver uses ITS OWN
 * coding rate and payload length, so only the correct CR yields a valid CRC.
 * That requires knowing the length in advance, which an explicit-mode capture
 * of the same frame supplies.
 *
 * Hence: MOD <sf> <bw> <cr> <hdr> <len>. Defaults are LongFast, explicit.
 * bw is the raw SX126x index -- 0x04=125k, 0x05=250k, 0x06=500k -- passed
 * through rather than translated, so what reaches the part is what was asked
 * for and a typo cannot silently become a different bandwidth.
 */
static uint8_t rx_sf   = 11;
static uint8_t rx_bw   = 0x05;
static uint8_t rx_cr   = 0x01;
static uint8_t rx_hdr  = 0x00;   /* 0 explicit, 1 implicit */
static uint8_t rx_len  = 0xFF;
static uint8_t rx_ldro = 0x00;

static const uint8_t rxcont_[3] = { 0xFF, 0xFF, 0xFF };

/* Push the current rx_* settings into the part and re-arm continuous receive. */
static void radio_apply_rx(void)
{
    uint8_t sb = 0x00;
    sx_cmd(CMD_SET_STANDBY, &sb, 1);
    uint8_t mod[4] = { rx_sf, rx_bw, rx_cr, rx_ldro };
    sx_cmd(CMD_SET_MODULATION_PARAMS, mod, 4);
    uint8_t pkt[6] = { 0x00, 0x10, rx_hdr, rx_len, 0x01, 0x00 };
    sx_cmd(CMD_SET_PACKET_PARAMS, pkt, 6);
    uint8_t clr[2] = { 0xFF, 0xFF };
    sx_cmd(CMD_CLR_IRQ_STATUS, clr, 2);
    sx_cmd(CMD_SET_RX, (uint8_t *)rxcont_, 3);
    printf("MODOK sf=%u bw=0x%02X cr=%u hdr=%u len=%u ldro=%u\n",
           rx_sf, rx_bw, rx_cr, rx_hdr, rx_len, rx_ldro);
    fflush(stdout);
}

/* Transmit power in dBm, settable at runtime via the PWR command.
 *
 * WHY THIS IS RUNTIME AND NOT A CONSTANT
 * --------------------------------------
 * Measuring a stock node's SNR-scaled contention window needs frames arriving
 * at a RANGE of signal levels. The boards are at a fixed 3 m, so the only
 * variable available is our output power. This is the knob that turns a
 * one-sample observation into a sweep.
 *
 * Range is set by the PA configuration below: paDutyCycle 0x02 / hpMax 0x02 is
 * the datasheet's +14 dBm setting, valid from -9 to +14 dBm. Values outside
 * that are clamped rather than passed through -- the SX1262 does not validate
 * them and out-of-range values produce undefined output, which would corrupt a
 * sweep silently. */
static int8_t tx_power_dbm = 10;

#define TX_POWER_MIN (-9)
#define TX_POWER_MAX (14)

static void radio_tx(const uint8_t *buf, uint8_t len)
{
    uint8_t sb = 0x00;
    sx_cmd(CMD_SET_STANDBY, &sb, 1);

    /* +14 dBm PA configuration, then a low output power. The boards are ~3 m
     * apart; nothing about the frame bytes depends on power, so there is no
     * reason to run hot. */
    uint8_t pa[4] = { 0x02, 0x02, 0x00, 0x01 };
    sx_cmd(CMD_SET_PA_CONFIG, pa, 4);
    uint8_t txp[2] = { (uint8_t)tx_power_dbm, 0x04 };   /* settable dBm, 200 us ramp */
    sx_cmd(CMD_SET_TX_PARAMS, txp, 2);

    /* Packet params must carry THIS frame's length. */
    uint8_t pkt[6] = { 0x00, 0x10, 0x00, len, 0x01, 0x00 };
    sx_cmd(CMD_SET_PACKET_PARAMS, pkt, 6);

    uint8_t base[2] = { 0x00, 0x00 };
    sx_cmd(CMD_SET_BUFFER_BASE_ADDR, base, 2);
    sx_write_buffer(0x00, buf, len);

    uint8_t clr[2] = { 0xFF, 0xFF };
    sx_cmd(CMD_CLR_IRQ_STATUS, clr, 2);
    uint8_t to[3] = { 0x00, 0x00, 0x00 };     /* no timeout */
    sx_cmd(CMD_SET_TX, to, 3);

    for (int i = 0; i < 500; i++) {
        vTaskDelay(1);
        uint8_t s2[2] = {0};
        sx_read(CMD_GET_IRQ_STATUS, s2, 2);
        uint16_t f = ((uint16_t)s2[0] << 8) | s2[1];
        if (f & IRQ_TX_DONE) {
            sx_cmd(CMD_CLR_IRQ_STATUS, clr, 2);
            printf("TXDONE len=%u\n", len);
            fflush(stdout);
            return;
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    printf("TXFAIL len=%u\n", len);
    fflush(stdout);
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void radio_reset(void)
{
    gpio_set_level(PIN_RST, 0);
    vTaskDelay(1);                 /* >= 1 tick; pdMS_TO_TICKS(2) is 0 here */
    gpio_set_level(PIN_RST, 1);
    vTaskDelay(pdMS_TO_TICKS(20));
    busy_wait();
}

void app_main(void)
{
    /* UART0 carries BOTH the log and the command channel, and that is the
     * whole difficulty. Installing a driver on the console UART without
     * telling stdio about it leaves two writers on one peripheral: printf
     * goes through the VFS path while uart_read_bytes drives the driver, and
     * the collision corrupts output ("0TXDONE") and can block the writer long
     * enough to starve the idle task and trip the task watchdog.
     *
     * Routing stdio through the same driver makes them one writer. Done first,
     * before any logging, so no output is emitted through the other path. */
    uart_config_t uc = { .baud_rate = 115200, .data_bits = UART_DATA_8_BITS,
                         .parity = UART_PARITY_DISABLE, .stop_bits = UART_STOP_BITS_1,
                         .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
                         .source_clk = UART_SCLK_DEFAULT };
    ESP_ERROR_CHECK(uart_driver_install(UART_NUM_0, 2048, 2048, 0, NULL, 0));
    ESP_ERROR_CHECK(uart_param_config(UART_NUM_0, &uc));
    uart_vfs_dev_use_driver(UART_NUM_0);
    setvbuf(stdout, NULL, _IOLBF, 0);      /* whole lines, never half of one */

    gpio_config_t out = { .pin_bit_mask = (1ULL << PIN_RST),
                          .mode = GPIO_MODE_OUTPUT };
    gpio_config(&out);
    gpio_config_t in = { .pin_bit_mask = (1ULL << PIN_BUSY) | (1ULL << PIN_DIO1),
                         .mode = GPIO_MODE_INPUT };
    gpio_config(&in);

    spi_bus_config_t bus = { .mosi_io_num = PIN_MOSI, .miso_io_num = PIN_MISO,
                             .sclk_io_num = PIN_SCK, .quadwp_io_num = -1,
                             .quadhd_io_num = -1, .max_transfer_sz = 300 };
    ESP_ERROR_CHECK(spi_bus_initialize(SPI2_HOST, &bus, SPI_DMA_CH_AUTO));
    spi_device_interface_config_t dev = { .clock_speed_hz = 2 * 1000 * 1000,
                                          .mode = 0, .spics_io_num = PIN_NSS,
                                          .queue_size = 1 };
    ESP_ERROR_CHECK(spi_bus_add_device(SPI2_HOST, &dev, &spi));

    radio_reset();

    /* Stage 1 — prove SPI and the pinout before trusting anything else. */
    uint8_t st = 0;
    sx_read(CMD_GET_STATUS, &st, 1);
    ESP_LOGI(TAG, "GetStatus=0x%02X (chipmode=%u cmdstat=%u)",
             st, (st >> 4) & 7, (st >> 1) & 7);

    uint8_t sb = 0x00;                                   /* STDBY_RC */
    sx_cmd(CMD_SET_STANDBY, &sb, 1);

    uint8_t reg = 0x01;                                  /* DC-DC */
    sx_cmd(CMD_SET_REGULATOR_MODE, &reg, 1);

    /* Heltec V3 clocks the SX1262 from a TCXO on DIO3. Without this the part
     * never gets a stable clock and receives nothing, which looks identical
     * to a wrong sync word. 1.8 V, ~5 ms startup (320 * 15.625 us). */
    uint8_t tcxo[4] = { 0x02, 0x00, 0x01, 0x40 };
    sx_cmd(CMD_SET_DIO3_AS_TCXO, tcxo, 4);
    uint8_t cal = 0x7F;
    sx_cmd(CMD_CALIBRATE, &cal, 1);
    vTaskDelay(pdMS_TO_TICKS(20));
    busy_wait();

    uint8_t rfsw = 0x01;
    sx_cmd(CMD_SET_DIO2_AS_RFSWITCH, &rfsw, 1);

    uint8_t pt = 0x01;                                   /* LoRa */
    sx_cmd(CMD_SET_PACKET_TYPE, &pt, 1);

    /* 906.875 MHz -> f * 2^25 / 32e6 = 0x38AE0000 */
    uint8_t freq[4] = { 0x38, 0xAE, 0x00, 0x00 };
    sx_cmd(CMD_SET_RF_FREQUENCY, freq, 4);

    /* SF11, BW 250 kHz (0x05), CR 4/5 (0x01), LDRO off */
    uint8_t mod[4] = { 11, 0x05, 0x01, 0x00 };
    sx_cmd(CMD_SET_MODULATION_PARAMS, mod, 4);

    /* preamble 16, explicit header, max payload, CRC on, standard IQ */
    uint8_t pkt[6] = { 0x00, 0x10, 0x00, 0xFF, 0x01, 0x00 };
    sx_cmd(CMD_SET_PACKET_PARAMS, pkt, 6);

    sx_write_reg(REG_LORA_SYNC_WORD_MSB, 0x24);
    sx_write_reg(REG_LORA_SYNC_WORD_LSB, 0xB4);
    ESP_LOGI(TAG, "sync word readback: %02X %02X",
             sx_read_reg(REG_LORA_SYNC_WORD_MSB), sx_read_reg(REG_LORA_SYNC_WORD_LSB));

    uint8_t base[2] = { 0x00, 0x00 };
    sx_cmd(CMD_SET_BUFFER_BASE_ADDR, base, 2);

    /* TX_DONE must be in the mask too. SetDioIrqParams' first field ENABLES
     * events; an event outside the mask never latches in the IRQ status
     * register, so a transmit completes silently and reads as a failure. */
    uint16_t mask = IRQ_RX_DONE | IRQ_CRC_ERR | IRQ_TIMEOUT | IRQ_HDR_ERR | IRQ_TX_DONE;
    uint8_t irq[8] = { (uint8_t)(mask >> 8), (uint8_t)mask,
                       (uint8_t)(mask >> 8), (uint8_t)mask, 0, 0, 0, 0 };
    sx_cmd(CMD_SET_DIO_IRQ_PARAMS, irq, 8);

    uint8_t errs[2] = {0};
    sx_read(CMD_GET_DEVICE_ERRORS, errs, 2);
    ESP_LOGI(TAG, "device errors: %02X%02X", errs[0], errs[1]);

    uint8_t rxcont[3] = { 0xFF, 0xFF, 0xFF };            /* continuous RX */
    sx_cmd(CMD_SET_RX, rxcont, 3);

    sx_read(CMD_GET_STATUS, &st, 1);
    ESP_LOGI(TAG, "RX armed, status=0x%02X. 906.875MHz SF11 BW250 CR4/5 sync 24B4", st);
    ESP_LOGI(TAG, "RAWFRAME lines follow: len,rssi,snr,hex");

    static char line[600];
    static int fill = 0;
    static uint8_t txbuf[256];

    uint32_t n = 0;
    while (1) {
        uint8_t ch;
        while (uart_read_bytes(UART_NUM_0, &ch, 1, 0) == 1) {
            if (ch == '\r' || ch == '\n') {
                line[fill] = 0;
                if (fill > 4 && line[0] == 'M' && line[1] == 'O' &&
                    line[2] == 'D' && line[3] == ' ') {
                    /* MOD <sf> <bw> <cr> <hdr> <len> -- decimal, except bw and
                     * len which accept 0x.. as well. Missing trailing fields
                     * keep their current value. */
                    unsigned v[6]; int got = 0; const char *q = line + 4;
                    while (got < 6 && *q) {
                        while (*q == ' ') q++;
                        if (!*q) break;
                        unsigned base = 10;
                        if (q[0] == '0' && (q[1] == 'x' || q[1] == 'X')) { base = 16; q += 2; }
                        unsigned acc = 0; int digits = 0;
                        while (*q) {
                            int d = hexval(*q);
                            if (d < 0 || (unsigned)d >= base) break;
                            acc = acc * base + (unsigned)d; digits++; q++;
                        }
                        if (!digits) break;
                        v[got++] = acc;
                    }
                    if (got >= 3) {
                        if (v[0] >= 5 && v[0] <= 12) rx_sf = (uint8_t)v[0];
                        rx_bw = (uint8_t)v[1];
                        if (v[2] >= 1 && v[2] <= 4) rx_cr = (uint8_t)v[2];
                        if (got >= 4) rx_hdr = v[3] ? 1 : 0;
                        if (got >= 5) rx_len = (uint8_t)v[4];
                        if (got >= 6) rx_ldro = v[5] ? 1 : 0;
                        radio_apply_rx();
                    } else {
                        printf("MODBAD\n"); fflush(stdout);
                    }
                    fill = 0;
                    continue;
                }
                if (fill > 4 && line[0] == 'P' && line[1] == 'W' &&
                    line[2] == 'R' && line[3] == ' ') {
                    /* PWR <signed dBm>. Clamped, and the ACTUAL value applied
                     * is echoed -- a sweep that silently ran at a different
                     * power than it recorded would be worse than no sweep. */
                    int sign = 1, i = 4, val = 0, digits = 0;
                    if (line[i] == '-') { sign = -1; i++; }
                    else if (line[i] == '+') { i++; }
                    for (; line[i] >= '0' && line[i] <= '9'; i++) {
                        val = val * 10 + (line[i] - '0');
                        digits++;
                    }
                    if (digits > 0) {
                        int want = sign * val;
                        if (want < TX_POWER_MIN) want = TX_POWER_MIN;
                        if (want > TX_POWER_MAX) want = TX_POWER_MAX;
                        tx_power_dbm = (int8_t)want;
                        printf("PWROK %d\n", (int)tx_power_dbm);
                    } else {
                        printf("PWRBAD\n");
                    }
                    fflush(stdout);
                } else if (fill > 3 && line[0] == 'T' && line[1] == 'X' && line[2] == ' ') {
                    int len = 0;
                    for (int i = 3; line[i] && line[i + 1] && len < (int)sizeof(txbuf); i += 2) {
                        int hi = hexval(line[i]), lo = hexval(line[i + 1]);
                        if (hi < 0 || lo < 0) { len = -1; break; }
                        txbuf[len++] = (uint8_t)((hi << 4) | lo);
                    }
                    if (len > 0) {
                        radio_tx(txbuf, (uint8_t)len);
                        /* Restore the receive packet params and re-arm. */
                        uint8_t rxpkt[6] = { 0x00, 0x10, 0x00, 0xFF, 0x01, 0x00 };
                        sx_cmd(CMD_SET_PACKET_PARAMS, rxpkt, 6);
                        sx_cmd(CMD_SET_RX, rxcont, 3);
                    } else {
                        printf("TXBADHEX\n"); fflush(stdout);
                    }
                }
                fill = 0;
            } else if (fill < (int)sizeof(line) - 1) {
                line[fill++] = (char)ch;
            }
        }
        uint8_t s[2] = {0};
        sx_read(CMD_GET_IRQ_STATUS, s, 2);
        uint16_t flags = ((uint16_t)s[0] << 8) | s[1];
        if (flags) {
            uint8_t clr[2] = { s[0], s[1] };
            sx_cmd(CMD_CLR_IRQ_STATUS, clr, 2);

            if (flags & IRQ_RX_DONE) {
                uint8_t bs[2] = {0};
                sx_read(CMD_GET_RX_BUFFER_STATUS, bs, 2);
                uint8_t len = bs[0], off = bs[1];
                uint8_t ps[3] = {0};
                sx_read(CMD_GET_PACKET_STATUS, ps, 3);
                int rssi = -((int)ps[0]) / 2;
                int snr  = ((int8_t)ps[1]) / 4;

                static uint8_t buf[256];
                if (len > sizeof(buf)) len = sizeof(buf);
                sx_read_buffer(off, buf, len);

                /* Verbatim. Nothing here parses the bytes: the layout is what
                 * we are trying to learn, and a sniffer that assumes it cannot
                 * discover it. CRC state is reported so a bad frame is never
                 * mistaken for a good one. */
                printf("RAWFRAME %lu len=%u rssi=%d snr=%d crc=%s hex=",
                       (unsigned long)(++n), len, rssi, snr,
                       (flags & IRQ_CRC_ERR) ? "BAD" : "ok");
                for (int i = 0; i < len; i++) printf("%02x", buf[i]);
                printf("\n");
                fflush(stdout);
            } else if (flags & (IRQ_HDR_ERR | IRQ_CRC_ERR)) {
                ESP_LOGW(TAG, "irq=%04X (header or CRC error)", flags);
            }
            sx_cmd(CMD_SET_RX, rxcont, 3);     /* re-arm */
        }
        /* One TICK, not pdMS_TO_TICKS(5). At the default 100 Hz tick rate
         * pdMS_TO_TICKS(5) rounds to ZERO, and vTaskDelay(0) does not yield —
         * so the "5 ms delay" was a busy loop that starved the idle task and
         * tripped the task watchdog on every transmit. A sub-tick delay is
         * not expressible; asking for one silently asks for none. */
        vTaskDelay(1);
    }
}
