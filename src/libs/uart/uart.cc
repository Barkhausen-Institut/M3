/****************************************************************************
 *                                                                          *
 *          libuart - Helper Functions for Serial Communication on M3       *
 *                                                                          *
 *                   Copyright (c) 2022 - 2023 Sebastian Haas               *
 *                                 2023        Till Miemietz                *
 ****************************************************************************/



/****************************************************************************
 *                                                                          *
 *                           include statements                             *
 *                                                                          *
 ****************************************************************************/


#include <base/stream/Serial.h>
#include <base/time/Instant.h>
#include <base/TMIF.h>                  // TileMux interface for mapping iomem
#include <base/KIF.h>

#include <string.h>

#include <uart/uart.h>

using namespace m3;

/****************************************************************************
 *                                                                          *
 *                        (module) global variables                         *
 *                                                                          *
 ****************************************************************************/


/* Physical base address of UART interface, used for mapping only           */
static volatile uint32_t *uart_base_phy =   (uint32_t*) 0x04000000;

/* Virtual addresses for accessing the UART interface after mapping the     *
 * corresponding page. Note that initializing the UART inteface will use    *
 * one page of memory, starting at address 0x24000000. TODO: Make the       *
 * virtual base address of the UART interface configurable to avoid         *
 * collisons                                                                */
static volatile uint32_t *uart_base   = (uint32_t*) 0x24000000;
static volatile uint32_t *uart_txdata = (uint32_t*) 0x24000000;
static volatile uint32_t *uart_rxdata = (uint32_t*) 0x24000004;
static volatile uint32_t *uart_txctrl = (uint32_t*) 0x24000008;
static volatile uint32_t *uart_rxctrl = (uint32_t*) 0x2400000C;
static volatile uint32_t *uart_div    = (uint32_t*) 0x24000018;

/* Currently not used                                                       */
UNUSED static volatile uint32_t *uart_ie     = (uint32_t*) 0x24000010;
UNUSED static volatile uint32_t *uart_ip     = (uint32_t*) 0x24000014;

/****************************************************************************
 *                                                                          *
 *                          function implementation                         *
 *                                                                          *
 ****************************************************************************/


/***              functions for logging as defined in uart.h              ***/

/* Set up the UART interface                                                */
void uart_init() {
    // First, map the UART memory into our AS
    TMIF::map((uintptr_t) uart_base, (goff_t) uart_base_phy, 1, KIF::Perm::RW);

	// Enable TX and RX channels
	*uart_txctrl = TXCTRL_TXEN;
	*uart_rxctrl = RXCTRL_RXEN;

	// Set baud rate
	*uart_div = CORE_CLK_FREQ_MHZ * 1000000 / (UART_BAUD_RATE - 1);
}

void uart_status() {
    uint32_t rx;
    Serial::get() << "UART status:\n";
    for (size_t i = 0; i < 7; i++) {
        rx = uart_base[i];
        Serial::get() << i << fmt("#x", rx) << "\n";
    }
}

int uart_fifo_write(const uint8_t *tx_data, int size) {
	int i;
	for (i = 0; i < size && !(*uart_txdata & TXDATA_FULL); i++)
		*uart_txdata = (int)tx_data[i];

	return i;
}

int uart_fifo_poll(uint8_t *c) {
	uint32_t val = *uart_rxdata;

	if (val & RXDATA_EMPTY)
		return -1;

	*c = (uint8_t)(val & RXDATA_MASK);

	return 0;
}

int uart_fifo_read(uint8_t *rx_data, const int size) {
	int i;
    uint8_t rxchar;

	for (i = 0; i < size; i++) {
        // loop until a character was received
        while (uart_fifo_poll(&rxchar) == -1)
            ;

        rx_data[i] = rxchar;

        // wait a bit when more chars are coming
        auto end = TimeInstant::now() + TimeDuration::from_millis(UART_RX_WAIT_MS);
        while(TimeInstant::now() < end)
            ;
	}

    rx_data[i] = '\0';
	return i;
}
