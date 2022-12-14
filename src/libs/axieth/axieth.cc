/*
 * Copyright (C) 2021-2022 Nils Asmussen, Barkhausen Institut
 *
 * This file is part of M3 (Microkernel-based SysteM for Heterogeneous Manycores).
 *
 * M3 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * M3 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License version 2 for more details.
 */

#include <base/stream/Serial.h>
#include <base/TMIF.h>
#include <base/KIF.h>

#include "xaxidma.h"
#include "xaxiethernet.h"
#include "xparameters.h"
#include "xllfifo.h"
#include "sleep.h"

#define AXIETHERNET_DEVICE_ID   XPAR_AXIETHERNET_0_DEVICE_ID
#define DMA_DEV_ID              XPAR_AXI_DMA_0_DEVICE_ID

#define RX_BD_SPACE_PHYS    (phys_base)
#define RX_BD_SPACE_BASE    (virt_base)
#define RX_BD_SPACE_HIGH    (virt_base + 0x0000FFFF)
#define TX_BD_SPACE_PHYS    (phys_base + 0x00010000)
#define TX_BD_SPACE_BASE    (virt_base + 0x00010000)
#define TX_BD_SPACE_HIGH    (virt_base + 0x0001FFFF)
#define TX_BUFFER_BASE      (virt_base + 0x00020000)
#define RX_BUFFER_PHYS      (phys_base + 0x00021000)
#define RX_BUFFER_SIZE      (2 * 1024 * 1024)

#define MAX_PKT_LEN         0x1000

#define COALESCING_COUNT    1
#define DELAY_TIMER_COUNT   XAXIDMA_NO_CHANGE

#define AXIETHERNET_LOOPBACK_SPEED  100 /* 100Mb/s for Mii */
#define AXIETHERNET_LOOPBACK_SPEED_1G   1000    /* 1000Mb/s for GMii */

#define RX_INTR_ID          5
#define TX_INTR_ID          4

// Marvell PHY 88E1510 Specific definitions
#define PHY_R0_CTRL_REG		     0
#define PHY_R21_2_MAC_CTRL_REG   21
#define PHY_R22_PAGE_ADDR_REG    22

#define PHY_R0_RESET         0x8000
#define PHY_R0_LOOPBACK      0x4000
#define PHY_R0_ANEG_ENABLE   0x1000
#define PHY_R0_DFT_SPD_MASK  0x2040
#define PHY_R0_DFT_SPD_10    0x0000
#define PHY_R0_DFT_SPD_100   0x2000
#define PHY_R0_DFT_SPD_1000  0x0040
#define PHY_R0_ISOLATE       0x0400

#define PHY_REG21_2_TX_DLY   0x0010 // bit 4
#define PHY_REG21_2_RX_DLY   0x0020 // bit 5

static goff_t virt_base;
static goff_t phys_base;
static XAxiDma AxiDma;
static XAxiEthernet AxiEthernetInstance;
static u8 LocalMacAddr[6] = {0x00, 0x0A, 0x35, 0x03, 0x02, 0x03};

static int PhySetup(XAxiEthernet *AxiEthernetInstancePtr)
{
    u16 PhyReg0;
    u32 PhyAddr;

    u16 PhyReg21_2 = 0; // MAC Specific Control Register 2, page 2
    u16 PhyReg21_2_read = 0;

    PhyAddr = XPAR_AXIETHERNET_0_PHYADDR;

    // Switching to PAGE2
    XAxiEthernet_PhyWrite(AxiEthernetInstancePtr,
                PhyAddr,
                PHY_R22_PAGE_ADDR_REG, 2);

    // read reg21_2
    XAxiEthernet_PhyRead(AxiEthernetInstancePtr, PhyAddr,
        PHY_R21_2_MAC_CTRL_REG, &PhyReg21_2_read);

    PhyReg21_2 |= PhyReg21_2_read;

    // Enable Rx delay, disable Tx delay
    PhyReg21_2 |= PHY_REG21_2_RX_DLY;
    PhyReg21_2 &= (~PHY_REG21_2_TX_DLY);
    XAxiEthernet_PhyWrite(AxiEthernetInstancePtr,
                PhyAddr,
                PHY_R21_2_MAC_CTRL_REG, PhyReg21_2);

    // Switching to PAGE0
    XAxiEthernet_PhyWrite(AxiEthernetInstancePtr,
                PhyAddr,
                PHY_R22_PAGE_ADDR_REG, 0);

    // Clear the PHY of any existing bits by zeroing this out
    PhyReg0 = 0;
    XAxiEthernet_PhyRead(AxiEthernetInstancePtr, PhyAddr,
                 PHY_R0_CTRL_REG, &PhyReg0);

    PhyReg0 &= (~PHY_R0_ANEG_ENABLE);
    PhyReg0 &= (~PHY_R0_ISOLATE);
    PhyReg0 |= PHY_R0_DFT_SPD_1000;

    XAxiEthernet_PhyWrite(AxiEthernetInstancePtr, PhyAddr,
                PHY_R0_CTRL_REG,
                PhyReg0 | PHY_R0_RESET);

    // Wait for PHY to reset
    sleep(4);

    return 0;
}

static int alloc_buffer(XAxiDma_BdRing *RxRingPtr, uintptr_t bufPhys) {
    XAxiDma_Bd *BdPtr;
    int Status;

    Status = XAxiDma_BdRingAlloc(RxRingPtr, 1, &BdPtr);
    if (Status != 0) {
        xdbg_printf(XDBG_DEBUG_DMA_ALL, "Rx bd alloc failed with {}\n", Status);
        return 1;
    }

    Status = XAxiDma_BdSetBufAddr(BdPtr, bufPhys);
    if (Status != 0) {
        xdbg_printf(XDBG_DEBUG_DMA_ALL,
            "Rx set buffer addr {:#x} on BD {:#x} failed {}\n", bufPhys, (void*)BdPtr, Status);
        return 1;
    }

    Status = XAxiDma_BdSetLength(BdPtr, MAX_PKT_LEN,
                RxRingPtr->MaxTransferLen);
    if (Status != 0) {
        xdbg_printf(XDBG_DEBUG_DMA_ALL,
            "Rx set length {} on BD {:#x} failed {}\n", MAX_PKT_LEN, (void*)BdPtr, Status);
        return 1;
    }

    /* Receive BDs do not need to set anything for the control
     * The hardware will set the SOF/EOF bits per stream status
     */
    XAxiDma_BdSetCtrl(BdPtr, 0);

    XAxiDma_BdSetId(BdPtr, bufPhys);

    Status = XAxiDma_BdRingToHw(RxRingPtr, 1, BdPtr);
    if (Status != 0) {
        xdbg_printf(XDBG_DEBUG_DMA_ALL, "Rx ToHw failed with {}\n", Status);
        return 1;
    }

    return 0;
}

static int RxSetup(XAxiDma * AxiDmaInstPtr)
{
    XAxiDma_BdRing *RxRingPtr;
    int Status;
    XAxiDma_Bd BdTemplate;
    int BdCount;
    int FreeBdCount;
    UINTPTR RxBufferPtr;
    int Index;

    RxRingPtr = XAxiDma_GetRxRing(AxiDmaInstPtr);

    /* Disable all RX interrupts before RxBD space setup */
    XAxiDma_BdRingIntDisable(RxRingPtr, XAXIDMA_IRQ_ALL_MASK);

    /* Setup Rx BD space */
    BdCount = XAxiDma_BdRingCntCalc(XAXIDMA_BD_MINIMUM_ALIGNMENT,
                RX_BD_SPACE_HIGH - RX_BD_SPACE_BASE + 1);

    Status = XAxiDma_BdRingCreate(RxRingPtr, RX_BD_SPACE_PHYS,
                    RX_BD_SPACE_BASE,
                    XAXIDMA_BD_MINIMUM_ALIGNMENT, BdCount);
    if (Status != 0) {
        xdbg_printf(XDBG_DEBUG_DMA_ALL, "Rx bd create failed with {}\n", Status);
        return 1;
    }

    /*
     * Setup a BD template for the Rx channel. Then copy it to every RX BD.
     */
    XAxiDma_BdClear(&BdTemplate);
    Status = XAxiDma_BdRingClone(RxRingPtr, &BdTemplate);
    if (Status != 0) {
        xdbg_printf(XDBG_DEBUG_DMA_ALL, "Rx bd clone failed with {}\n", Status);
        return 1;
    }

    /* Attach buffers to RxBD ring so we are ready to receive packets */
    FreeBdCount = XAxiDma_BdRingGetFreeCnt(RxRingPtr);
    if(RX_BUFFER_SIZE < FreeBdCount * MAX_PKT_LEN) {
        xdbg_printf(XDBG_DEBUG_DMA_ALL,
                    "Reduced bd count from {} to {} to meet receive buffer size\n",
                    FreeBdCount, RX_BUFFER_SIZE / MAX_PKT_LEN);
        FreeBdCount = RX_BUFFER_SIZE / MAX_PKT_LEN;
    }

    RxBufferPtr = RX_BUFFER_PHYS;
    for (Index = 0; Index < FreeBdCount; Index++) {
        if(alloc_buffer(RxRingPtr, RxBufferPtr)) {
            xdbg_printf(XDBG_DEBUG_DMA_ALL, "Unable to allocate receive buffers\n");
            return 1;
        }
        RxBufferPtr += MAX_PKT_LEN;
    }

    Status = XAxiDma_BdRingSetCoalesce(RxRingPtr, COALESCING_COUNT,
            DELAY_TIMER_COUNT);
    if (Status != 0) {
        xdbg_printf(XDBG_DEBUG_DMA_ALL, "Rx set coalesce failed with {}\n", Status);
        return 1;
    }

    /* Enable all RX interrupts */
    XAxiDma_BdRingIntEnable(RxRingPtr, XAXIDMA_IRQ_ALL_MASK);

    /* Start RX DMA channel */
    Status = XAxiDma_BdRingStart(RxRingPtr);
    if (Status != 0) {
        xdbg_printf(XDBG_DEBUG_DMA_ALL, "Rx start BD ring failed with {}\n", Status);
        return 1;
    }

    return 0;
}

static int TxSetup(XAxiDma * AxiDmaInstPtr)
{
    XAxiDma_BdRing *TxRingPtr = XAxiDma_GetTxRing(AxiDmaInstPtr);
    XAxiDma_Bd BdTemplate;
    int Status;
    u32 BdCount;

    /* Disable all TX interrupts before TxBD space setup */
    XAxiDma_BdRingIntDisable(TxRingPtr, XAXIDMA_IRQ_ALL_MASK);

    /* Setup TxBD space  */
    BdCount = XAxiDma_BdRingCntCalc(XAXIDMA_BD_MINIMUM_ALIGNMENT,
            (UINTPTR)TX_BD_SPACE_HIGH - (UINTPTR)TX_BD_SPACE_BASE + 1);

    Status = XAxiDma_BdRingCreate(TxRingPtr, TX_BD_SPACE_PHYS,
                     TX_BD_SPACE_BASE,
                     XAXIDMA_BD_MINIMUM_ALIGNMENT, BdCount);
    if (Status != 0) {
        xdbg_printf(XDBG_DEBUG_DMA_ALL, "Failed create BD ring\n");
        return 1;
    }

    /*
     * Like the RxBD space, we create a template and set all BDs to be the
     * same as the template. The sender has to set up the BDs as needed.
     */
    XAxiDma_BdClear(&BdTemplate);
    Status = XAxiDma_BdRingClone(TxRingPtr, &BdTemplate);
    if (Status != 0) {
        xdbg_printf(XDBG_DEBUG_DMA_ALL, "Failed clone BDs\n");
        return 1;
    }

    Status = XAxiDma_BdRingSetCoalesce(TxRingPtr, COALESCING_COUNT,
            DELAY_TIMER_COUNT);
    if (Status != 0) {
        xdbg_printf(XDBG_DEBUG_DMA_ALL,
            "Failed set coalescing: {}/{}\n", COALESCING_COUNT, DELAY_TIMER_COUNT);
        return 1;
    }

    /* Enable all TX interrupts */
    XAxiDma_BdRingIntEnable(TxRingPtr, XAXIDMA_IRQ_ALL_MASK);

    /* Start the TX channel */
    Status = XAxiDma_BdRingStart(TxRingPtr);
    if (Status != 0) {
        xdbg_printf(XDBG_DEBUG_DMA_ALL, "Failed bd start\n");
        return 1;
    }

    return 0;
}

static int init_mac(XAxiEthernet_Config *MacCfgPtr) {
    int Status;
    int LoopbackSpeed;

    /* Initialize AxiEthernet hardware */
    Status = XAxiEthernet_CfgInitialize(&AxiEthernetInstance, MacCfgPtr, MacCfgPtr->BaseAddress);
    if (Status != 0) {
        xdbg_printf(XDBG_DEBUG_ERROR, "AXI Ethernet initialization failed {}\n", Status);
        return 1;
    }

    /* Set the MAC  address */
    Status = XAxiEthernet_SetMacAddress(&AxiEthernetInstance, (u8*)LocalMacAddr);
    if (Status != 0) {
        xdbg_printf(XDBG_DEBUG_ERROR, "Error setting MAC address\n");
        return 1;
    }

    /*
     * Set PHY to loopback, speed depends on phy type.
     * MII is 100 and all others are 1000.
     */
    if (XAxiEthernet_GetPhysicalInterface(&AxiEthernetInstance) == XAE_PHY_TYPE_MII) {
        LoopbackSpeed = AXIETHERNET_LOOPBACK_SPEED;
    } else {
        LoopbackSpeed = AXIETHERNET_LOOPBACK_SPEED_1G;
    }

    /*
     * Set PHY<-->MAC data clock
     */
    Status =  XAxiEthernet_SetOperatingSpeed(&AxiEthernetInstance, (u16)LoopbackSpeed);
    if (Status != 0) {
        xdbg_printf(XDBG_DEBUG_ERROR, "Error setting operating speed\n");
        return 1;
    }

    xdbg_printf(XDBG_DEBUG_GENERAL, "MAC initialized, waiting 2sec...\n");

    /*
     * Setting the operating speed of the MAC needs a delay.  There
     * doesn't seem to be register to poll, so please consider this
     * during your application design.
     */
    sleep(2);

    xdbg_printf(XDBG_DEBUG_GENERAL, "MAC initialization done\n");

    return 0;
}

EXTERN_C ssize_t axieth_init(goff_t virt, goff_t phys, size_t size) {
        int Status;
    XAxiEthernet_Config *MacCfgPtr;
    XAxiDma_Config *Config;

    m3::Serial::init("net", m3::TileId::from_raw(m3::env()->tile_id));

    xdbg_printf(XDBG_DEBUG_GENERAL,
        "axieth_init(virt={:#x}, phys={:#x}, size={:#x})\n",
        virt, phys, size);

    virt_base = virt;
    phys_base = phys;
    if(RX_BUFFER_SIZE > size) {
        xdbg_printf(XDBG_DEBUG_ERROR, "Buffer space too small\n");
        return -1;
    }

    /* Get the configuration of AxiEthernet hardware */
    MacCfgPtr = XAxiEthernet_LookupConfig(AXIETHERNET_DEVICE_ID);

    // map AxiEthernet MMIO region
    m3::TMIF::map(MacCfgPtr->BaseAddress, MacCfgPtr->BaseAddress, 1, m3::KIF::Perm::RW);

    /* Check whether AXI DMA is present or not */
    if(MacCfgPtr->AxiDevType != XPAR_AXI_DMA) {
        xdbg_printf(XDBG_DEBUG_ERROR, "Device HW not configured for DMA mode\n");
        return -1;
    }

    Config = XAxiDma_LookupConfig(DMA_DEV_ID);
    if (!Config) {
        xdbg_printf(XDBG_DEBUG_ERROR, "No DMA config found for {}\n", DMA_DEV_ID);
        return -1;
    }

    // map AxiDMA MMIO region
    m3::TMIF::map(Config->BaseAddr, Config->BaseAddr, 1, m3::KIF::Perm::RW);

    /* Initialize DMA engine */
    Status = XAxiDma_CfgInitialize(&AxiDma, Config);
    if (Status != 0) {
        xdbg_printf(XDBG_DEBUG_ERROR, "DMA initialization failed {}\n", Status);
        return -1;
    }

    if(!XAxiDma_HasSg(&AxiDma)) {
        xdbg_printf(XDBG_DEBUG_ERROR, "DMA device configured as Simple mode \n");
        return -1;
    }

    xdbg_printf(XDBG_DEBUG_GENERAL, "DMA TX Setup\n");
    Status = TxSetup(&AxiDma);
    if (Status != 0) {
        return -1;
    }

    xdbg_printf(XDBG_DEBUG_GENERAL, "DMA RX Setup\n");
    Status = RxSetup(&AxiDma);
    if (Status != 0) {
        return -1;
    }

    init_mac(MacCfgPtr);

    xdbg_printf(XDBG_DEBUG_GENERAL, "Marvell PHY Setup\n");
    Status = PhySetup(&AxiEthernetInstance);
    if (Status != 0) {
        return -1;
    }

    /*
     * Make sure Tx and Rx are enabled
     */
    Status = XAxiEthernet_SetOptions(&AxiEthernetInstance,
                         XAE_RECEIVER_ENABLE_OPTION | XAE_TRANSMITTER_ENABLE_OPTION);
    if (Status != XST_SUCCESS) {
        xdbg_printf(XDBG_DEBUG_ERROR, "Error setting options");
        return XST_FAILURE;
    }

    /*
     * Start the Axi Ethernet and enable its ERROR interrupts
     */
    XAxiEthernet_Start(&AxiEthernetInstance);

    /**
     * Register interrupts
     */
    m3::TMIF::reg_irq(RX_INTR_ID);
    m3::TMIF::reg_irq(TX_INTR_ID);

    return static_cast<ssize_t>(TX_BUFFER_BASE);
}

EXTERN_C void axieth_deinit() {
    xdbg_printf(XDBG_DEBUG_GENERAL, "axieth_deinit()\n");

    XAxiEthernet_Stop(&AxiEthernetInstance);
}

static void handle_pending_sends() {
    XAxiDma_BdRing *TxRingPtr = XAxiDma_GetTxRing(&AxiDma);

    while(true) {
        // Read pending interrupts
        u32 IrqStatus = XAxiDma_BdRingGetIrq(TxRingPtr);
        xdbg_printf(XDBG_DEBUG_GENERAL, "TxIrqStatus = {:#x}\n", IrqStatus);

        // Acknowledge pending interrupts
        XAxiDma_BdRingAckIrq(TxRingPtr, IrqStatus);

        // error?
        if((IrqStatus & XAXIDMA_IRQ_ERROR_MASK) != 0) {
            xdbg_printf(XDBG_DEBUG_ERROR, "Error bit set in TxIrqStatus\n");
        }
        // completion interrupt?
        if(IrqStatus & (XAXIDMA_IRQ_DELAY_MASK | XAXIDMA_IRQ_IOC_MASK))
            break;
    }

    // Get all processed BDs from hardware
    XAxiDma_Bd *BdPtr;
    int BdCount = XAxiDma_BdRingFromHw(TxRingPtr, XAXIDMA_ALL_BDS, &BdPtr);
    // assert(BdCount == 1);

    // Handle the BDs
    XAxiDma_Bd *BdCurPtr = BdPtr;
    for (int Index = 0; Index < BdCount; Index++) {
        // Check the status in each BD
        // If error happens, the DMA engine will be halted after this
        // BD processing stops.
        u32 BdSts = XAxiDma_BdGetSts(BdCurPtr);
        if ((BdSts & XAXIDMA_BD_STS_ALL_ERR_MASK) ||
            (!(BdSts & XAXIDMA_BD_STS_COMPLETE_MASK))) {
            xdbg_printf(XDBG_DEBUG_ERROR, "Error bit set in transmit BD\n");
            break;
        }

        // Find the next processed BD
        BdCurPtr = (XAxiDma_Bd *)XAxiDma_BdRingNext(TxRingPtr, BdCurPtr);
    }

    // Free all processed BDs for future transmission
    int Status = XAxiDma_BdRingFree(TxRingPtr, BdCount, BdPtr);
    if (Status != XST_SUCCESS) {
        xdbg_printf(XDBG_DEBUG_ERROR, "Unable to free transmit BDs\n");
    }
}

EXTERN_C int axieth_send(void *packet, size_t len) {
    XAxiDma_BdRing *TxRingPtr = XAxiDma_GetTxRing(&AxiDma);
    XAxiDma_Bd *BdPtr;
    int Status;

    xdbg_printf(XDBG_DEBUG_GENERAL,
        "axieth_send(packet= {:p}, len={})\n", packet, len);

    // TODO is that correct?
    if (len > TxRingPtr->MaxTransferLen) {
        xdbg_printf(XDBG_DEBUG_ERROR,
            "FIFO has not enough space: need={}, have={}\n", len, TxRingPtr->MaxTransferLen);
        return 1;
    }

    Status = XAxiDma_BdRingAlloc(TxRingPtr, 1, &BdPtr);
    if (Status != 0) {
        xdbg_printf(XDBG_DEBUG_ERROR, "Failed bd alloc\n");
        return 1;
    }

    uintptr_t physAddr = (reinterpret_cast<uintptr_t>(packet) - virt_base) + phys_base;
    Status = XAxiDma_BdSetBufAddr(BdPtr, physAddr);
    if (Status != 0) {
        xdbg_printf(XDBG_DEBUG_ERROR, "BDSetBufAddr failed\n");
        return 1;
    }

    Status = XAxiDma_BdSetLength(BdPtr, len, TxRingPtr->MaxTransferLen);
    if (Status != 0) {
        xdbg_printf(XDBG_DEBUG_ERROR, "BDSetLength failed\n");
        return 1;
    }

    // the first BD has SOF set; the last has EOF and IOC set
    u32 CrBits = XAXIDMA_BD_CTRL_TXSOF_MASK | XAXIDMA_BD_CTRL_TXEOF_MASK;
    XAxiDma_BdSetCtrl(BdPtr, CrBits);
    XAxiDma_BdSetId(BdPtr, packet);

    // Give the BD to hardware
    Status = XAxiDma_BdRingToHw(TxRingPtr, 1, BdPtr);
    if (Status != 0) {
        xdbg_printf(XDBG_DEBUG_ERROR, "BdRingToHw failed\n");
        return 1;
    }

    handle_pending_sends();
    xdbg_printf(XDBG_DEBUG_GENERAL, "Sending done\n");

    return 0;
}

EXTERN_C size_t axieth_recv(void *buffer, size_t len) {
    XAxiDma_BdRing *RxRingPtr = XAxiDma_GetRxRing(&AxiDma);
    u32 IrqStatus;

    // Read pending interrupts
    IrqStatus = XAxiDma_BdRingGetIrq(RxRingPtr);
    // xdbg_printf(XDBG_DEBUG_GENERAL, "RxIrqStatus = {:#x}\n", IrqStatus);

    // Acknowledge pending interrupts
    XAxiDma_BdRingAckIrq(RxRingPtr, IrqStatus);

    // Get finished BDs from hardware
    XAxiDma_Bd *BdPtr;
    int BdCount = XAxiDma_BdRingFromHw(RxRingPtr, 1, &BdPtr);
    if(BdCount == 0)
        return 0;

    // Check the flags set by the hardware for status
    // If error happens, processing stops, because the DMA engine
    // is halted after this BD.
    u32 BdSts = XAxiDma_BdGetSts(BdPtr);
    if ((BdSts & XAXIDMA_BD_STS_ALL_ERR_MASK) ||
        (!(BdSts & XAXIDMA_BD_STS_COMPLETE_MASK))) {
        xdbg_printf(XDBG_DEBUG_ERROR, "Error bit set in receive BD\n");
        return 0;
    }

    // get length and buffer address
    int length = XAxiDma_BdGetActualLength(BdPtr, RxRingPtr->MaxTransferLen);
    uintptr_t bufPhys = XAxiDma_BdGetBufAddr(BdPtr);
    uintptr_t bufAddr = virt_base + (bufPhys - phys_base);

    xdbg_printf(XDBG_DEBUG_GENERAL, "Received packet of {} bytes @ {:#x}\n",
        length, (void*)bufAddr);

    if(static_cast<size_t>(length) > len) {
        xdbg_printf(XDBG_DEBUG_ERROR,
            "Packet too large for buffer ({} vs. {})\n", length, len);
        return 0;
    }

    // copy to caller buffer
    memcpy(buffer, reinterpret_cast<void*>(bufAddr), length);

    // free BD
    int Status = XAxiDma_BdRingFree(RxRingPtr, 1, BdPtr);
    if(Status != XST_SUCCESS) {
        xdbg_printf(XDBG_DEBUG_ERROR, "Freeing BD failed ({})\n", Status);
        return 0;
    }

    // allocate new BD for the next receive
    if(alloc_buffer(RxRingPtr, bufPhys)) {
        xdbg_printf(XDBG_DEBUG_ERROR, "Unable to allocate new receive buffer\n");
        return 0;
    }

    return static_cast<size_t>(length);
}
