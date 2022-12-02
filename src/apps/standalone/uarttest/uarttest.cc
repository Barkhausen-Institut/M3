
#include <base/stream/Serial.h>
#include <base/time/Instant.h>

#include <string.h>

using namespace m3;


volatile uint32_t *uart_base = (uint32_t*)0x04000000;

volatile uint32_t *uart_txdata = (uint32_t*)0x04000000;
volatile uint32_t *uart_rxdata = (uint32_t*)0x04000004;
volatile uint32_t *uart_txctrl = (uint32_t*)0x04000008;
volatile uint32_t *uart_rxctrl = (uint32_t*)0x0400000C;
volatile uint32_t *uart_ie     = (uint32_t*)0x04000010;
volatile uint32_t *uart_ip     = (uint32_t*)0x04000014;
volatile uint32_t *uart_div    = (uint32_t*)0x04000018;

#define RXDATA_EMPTY   (1UL << 31) // Receive FIFO Empty
#define RXDATA_MASK    0xFF        // Receive Data Mask
#define TXDATA_FULL    (1UL << 31) // Transmit FIFO Full
#define TXCTRL_TXEN    (1 << 0)    // Activate Tx Channel
#define RXCTRL_RXEN    (1 << 0)    // Activate Rx Channel
#define IE_TXWM        (1 << 0)    // TX Interrupt Enable/Pending
#define IE_RXWM        (1 << 1)    // RX Interrupt Enable/Pending

#define CORE_CLK_FREQ_MHZ 100
#define UART_BAUD_RATE    115200
#define UART_RX_WAIT_MS   1

#define MAX_RX_BUF_SIZE 500

//#define DO_ECHO


static void uart_init() {
	// Enable TX and RX channels
	*uart_txctrl = TXCTRL_TXEN;
	*uart_rxctrl = RXCTRL_RXEN;

	// Set baud rate
	*uart_div = CORE_CLK_FREQ_MHZ*1000000 / (UART_BAUD_RATE - 1);
}

static void uart_status() {
    uint32_t rx;
    logln("UART status:"_cf);
    for (size_t i=0; i<7; i++) {
        rx = uart_base[i];
        logln("[{}]: {:#x}"_cf, i, rx);
    }
}

static int uart_fifo_write(const uint8_t *tx_data, int size) {
	int i;
	for (i = 0; i < size && !(*uart_txdata & TXDATA_FULL); i++)
		*uart_txdata = (int)tx_data[i];

	return i;
}

static int uart_fifo_poll(uint8_t *c) {
	uint32_t val = *uart_rxdata;

	if (val & RXDATA_EMPTY)
		return -1;

	*c = (uint8_t)(val & RXDATA_MASK);

	return 0;
}

static int uart_fifo_read(uint8_t *rx_data, const int size) {
	int i;
    uint8_t rxchar;

	for (i = 0; i < size; i++) {
        if (uart_fifo_poll(&rxchar) == -1)
            break;
        else
            rx_data[i] = rxchar;

        //wait a bit when more chars are coming
        auto end = TimeInstant::now() + TimeDuration::from_millis(UART_RX_WAIT_MS);
        while(TimeInstant::now() < end)
            ;
	}

    rx_data[i] = '\0';
	return i;
}


int main() {
    uint8_t rx_buf[MAX_RX_BUF_SIZE+1];
    uint8_t txdata_char_help[] = "help\r";
    uint8_t txdata_char_list[] = "list\r";
    uint8_t txdata_char_read[] = "read 1KH1V.TXT\r";
    int num_recv_bytes = 0;

    logln("Starting UART test\n"_cf);


    uart_init();
    //uart_status();


    logln("Waiting for input..."_cf);

    while(1) {
        num_recv_bytes = uart_fifo_read(rx_buf, MAX_RX_BUF_SIZE);
        if (num_recv_bytes) {
            logln("Received {} byte:"_cf, num_recv_bytes);
            logln("{}"_cf, (const char*)rx_buf);

            //check special chars
            if (num_recv_bytes == 1) {
                if (rx_buf[0] == 'q') {
                    break;
                } else if (rx_buf[0] == 'h') {
                    uart_fifo_write(txdata_char_help, strlen((const char*)txdata_char_help));
                    continue;
                } else if (rx_buf[0] == 'l') {
                    uart_fifo_write(txdata_char_list, strlen((const char*)txdata_char_list));
                    continue;
                } else if (rx_buf[0] == 'r') {
                    uart_fifo_write(txdata_char_read, strlen((const char*)txdata_char_read));
                    continue;
                }
            }

#ifdef DO_ECHO
            uart_fifo_write(rx_buf, num_recv_bytes);
            logln("Echo: {} bytes"_cf, num_recv_bytes);
#endif
        }
    }


    // for the test infrastructure
    logln("Shutting down"_cf);
    return 0;
}
