/****************************************************************************   
 *                                                                          *   
 *          uart.h - Helper Functions for Serial Communication on M3        *   
 *                                                                          *   
 *                   Copyright (c) 2022 - 2023 Sebastian Haas               *   
 *                                 2023        Till Miemietz                *   
 ****************************************************************************/  


#pragma once

/****************************************************************************
 *                                                                          *
 *                     global definitions and macros                        *
 *                                                                          *
 ****************************************************************************/


/* Status flags for working with the UART interface                         */
#define RXDATA_EMPTY   (1UL << 31) // Receive FIFO Empty
#define RXDATA_MASK    0xFF        // Receive Data Mask
#define TXDATA_FULL    (1UL << 31) // Transmit FIFO Full
#define TXCTRL_TXEN    (1 << 0)    // Activate Tx Channel
#define RXCTRL_RXEN    (1 << 0)    // Activate Rx Channel
#define IE_TXWM        (1 << 0)    // TX Interrupt Enable/Pending
#define IE_RXWM        (1 << 1)    // RX Interrupt Enable/Pending

/* Configuration parameters for UART setup                                  */
#define CORE_CLK_FREQ_MHZ 100
#define UART_BAUD_RATE    115200
#define UART_RX_WAIT_MS   1

#define MAX_RX_BUF_SIZE 500

//#define DO_ECHO

/****************************************************************************
 *                                                                          *
 *                          function prototypes                             *
 *                                                                          *
 ****************************************************************************/


/* Initialize the UART interface                                            */
void uart_init();

/* Print some status information about the UART interface                   */
void uart_status();

/* Write something to the serial interface                                  */
int uart_fifo_write(const uint8_t *tx_data, int size);

/* Polls for available data, returns a byte read through c                  */
int uart_fifo_poll(uint8_t *c);

/* Reads size bytes from the interface                                      */
int uart_fifo_read(uint8_t *rx_data, const int size);
