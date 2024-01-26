/*
 * Copyright (c) 2016, Freescale Semiconductor, Inc.
 * Copyright 2016-2020,2022 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*******************************************************************************
 * Includes
 ******************************************************************************/

#include "lwip/opt.h"
#define BOARD_NETWORK_USE_100M_ENET_PORT 1
#if LWIP_IPV4 && LWIP_RAW

#include "ping.h"
#include "lwip/ip_addr.h"
#include "lwip/timeouts.h"
#include "lwip/init.h"
#include "lwip/ip.h"
#include "lwip/udp.h"
#include "lwip/raw.h"

#include "netif/ethernet.h"
#include "ethernetif.h"

#include "pin_mux.h"
#include "board.h"
#ifndef configMAC_ADDR
#include "fsl_silicon_id.h"
#endif
#include "fsl_phy.h"

#include "fsl_enet.h"
#include "fsl_phyksz8081.h"
#include "fsl_phyrtl8211f.h"
/*******************************************************************************
 * Definitions
 ******************************************************************************/
/* Global */
#define LWIP_RAW 1
#define LWIP_ARP 1
#define LWIP_UDP 1
#define LWIP_TIMERS 1
#define LWIP_IPV4 1

/* Keti */
#define DEFAULT_ETH_100M_ADDR(ipaddr)   IP4_ADDR(ipaddr, 192, 168, 137, 102);
#define DEFAULT_ETH_1G_ADDR(ipaddr)   	IP4_ADDR(ipaddr, 192, 168, 137, 105);
#define DEFAULT_ETH_GATEWAY(ipaddr)   	IP4_ADDR(ipaddr, 192, 168, 137, 2);
#define DEFAULT_ETH_NET_MASK(ipaddr)   	IP4_ADDR(ipaddr, 255, 255, 255, 255);
#define KETI_IPV4_ADDR_PAD(x)  x[0], x[1], x[2], x[3]
#define DEFAULT_UDP_PORT 4000

typedef enum Keti_Err{
    ERROR_NONE = 0,

} Keti_Err_e;
enum Keti_Eth_Type_e{
    Ethernet_100M = 0,
    Ethernet_1G,
};
enum Keti_Recver_State_e{
	Fireware_No_Response_From_ECU = 10,
	Fireware_Response_Info_From_ECU,
	Fireware_Wait_Indication_From_ECU,

	Model_No_Response_From_ECU = 20,
	Model_Response_Info_From_ECU,
	Model_Wait_Indication_From_ECU,
};
struct Eth_Addr_Info_t{
    uint8_t mac_addr[NETIF_MAX_HWADDR_LEN];
    ip4_addr_t src_addr;
    ip4_addr_t gw_addr;

    ethernetif_config_t enet_config;
    struct netif netif;
    struct udp_pcb *udp_pcb;
    struct tcp_pcb *tcp_pcb;
    struct raw_pcb *raw_pcb;

    u8_t *send_buf;
    u32_t send_timer;
    enum Keti_Recver_State_e rs;
};
struct Eth_Info_t{
    bool Eth_100M_On;
    struct Eth_Addr_Info_t *eth_100M;

    bool Eth_1G_On;
    struct Eth_Addr_Info_t *eth_1G;    
};


/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/
static u32_t ping_time;
static u16_t ping_seq_num;

extern phy_ksz8081_resource_t g_phy_resource_100M;
phy_ksz8081_resource_t g_phy_resource_100M;
extern phy_rtl8211f_resource_t g_phy_resource_1G;
phy_rtl8211f_resource_t g_phy_resource_1G;
static phy_handle_t g_phyHandle_100M;
static phy_handle_t g_phyHandle_1G;

char test_dump[] = {0x44,
					0x01,0x00,0x00,0x00,0x17,0x31,
					0x32,0x33,0x34,0x45,0x46,0x47,0x48,0x41,
					0x42,0x43,0x44,0x35,0x36,0x37,0x38,0x44,
					0xAA};
/*******************************************************************************
 * Functions
 ******************************************************************************/
static Keti_Err_e Keti_i_Ethernet_Interface_Initial(struct Eth_Info_t *eth_info, enum Keti_Eth_Type_e type, const struct Eth_Addr_Info_t *addr_info);
static Keti_Err_e Keti_s_Ethernet_Interface_Addr_Initial(enum Keti_Eth_Type_e type, struct Eth_Addr_Info_t *eth);
static u8_t Keti_Raw_Receiver(void *arg, struct raw_pcb *pcb, struct pbuf *p, const ip_addr_t *addr);
static void Keti_Eth_UDP_Receiver(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port);
static Keti_Err_e Keit_Eth_UDP_Sender(struct udp_pcb *pcb, struct raw_pcb *raw_pcb, u8_t *data, u16_t data_len);

static status_t MDIO_Write_100M(uint8_t phyAddr, uint8_t regAddr, uint16_t data);
static status_t MDIO_Read_100M(uint8_t phyAddr, uint8_t regAddr, uint16_t *pData);
static status_t MDIO_Write_1G(uint8_t phyAddr, uint8_t regAddr, uint16_t data);
static status_t MDIO_Read_1G(uint8_t phyAddr, uint8_t regAddr, uint16_t *pData);

static void Keti_Send_Timer(void *arg);

/*******************************************************************************
 * Code
 ******************************************************************************/
void BOARD_InitModuleClock(void)
{
    const clock_sys_pll1_config_t sysPll1Config = {
        .pllDiv2En = true,
    };
    CLOCK_InitSysPll1(&sysPll1Config);

    clock_root_config_t rootCfg_100M = {.mux = 4, .div = 10}; /* Generate 50M root clock. */
    CLOCK_SetRootClock(kCLOCK_Root_Enet1, &rootCfg_100M);

    clock_root_config_t rootCfg_1G = {.mux = 4, .div = 4}; /* Generate 125M root clock. */
    CLOCK_SetRootClock(kCLOCK_Root_Enet2, &rootCfg_1G);
}

void IOMUXC_SelectENETClock(void)
{
    IOMUXC_GPR->GPR4 |= IOMUXC_GPR_GPR4_ENET_REF_CLK_DIR_MASK; /* 50M ENET_REF_CLOCK output to PHY and ENET module. */
    IOMUXC_GPR->GPR5 |= IOMUXC_GPR_GPR5_ENET1G_RGMII_EN_MASK;
}

void BOARD_ENETFlexibleConfigure(enet_config_t *config, int type)
{
	switch(type)
	{
		case 0:
			config->miiMode = kENET_RmiiMode;

			break;
		case 1:
			config->miiMode = kENET_RgmiiMode;
			break;
		default:break;
	}
}

/*!
 * @brief Interrupt service for SysTick timer.
 */
void SysTick_Handler(void)
{
    time_isr();
}

/*!
 * @brief Main function.
 */
int main(void)
{
    BOARD_ConfigMPU();
    BOARD_InitPins();
    BOARD_BootClockRUN();
    BOARD_InitDebugConsole();
    BOARD_InitModuleClock();

    IOMUXC_SelectENETClock();

    time_init();
    lwip_init();

    Keti_Err_e err;
    struct Eth_Info_t eth_info;
    memset(&eth_info, 0x00, sizeof(struct Eth_Info_t));
    struct Eth_Addr_Info_t *addr_info = NULL;

    err = Keti_i_Ethernet_Interface_Initial(&eth_info, Ethernet_100M, addr_info); // eth_info 구조체의 값 초기화, Ethernet_100M 타입의 정보를 채움
    PRINTF("eth_info.Eth_100M_On:%d\n\r", eth_info.Eth_100M_On);
    PRINTF("IPv4 Address: %u.%u.%u.%u\n\r", ((u8_t *)&eth_info.eth_100M->src_addr)[0],
    										((u8_t *)&eth_info.eth_100M->src_addr)[1],
											((u8_t *)&eth_info.eth_100M->src_addr)[2],
											((u8_t *)&eth_info.eth_100M->src_addr)[3]);

    err = Keti_i_Ethernet_Interface_Initial(&eth_info, Ethernet_1G, addr_info);
    PRINTF("eth_info.Eth_1G_On:%d\n\r", eth_info.Eth_1G_On);
    PRINTF("IPv4 Address: %u.%u.%u.%u\n\r", ((u8_t *)&eth_info.eth_1G->src_addr)[0],
											((u8_t *)&eth_info.eth_1G->src_addr)[1],
											((u8_t *)&eth_info.eth_1G->src_addr)[2],
											((u8_t *)&eth_info.eth_1G->src_addr)[3]);

    err_t ret_err;
    eth_info.eth_100M->udp_pcb = (struct udp_pcb *)udp_new();
    eth_info.eth_100M->raw_pcb = (struct raw_pcb *)raw_new(IP_PROTO_UDP);
    memcpy(&eth_info.eth_100M->udp_pcb->local_ip, &eth_info.eth_100M->src_addr, sizeof(ip4_addr_t));
    memcpy(&eth_info.eth_100M->udp_pcb->remote_ip, &eth_info.eth_100M->gw_addr, sizeof(ip4_addr_t));
    u16_t local_port = 50000;
    u16_t remote_port = 50000;
    eth_info.eth_100M->udp_pcb->local_port = local_port;
    eth_info.eth_100M->udp_pcb->remote_port = remote_port;
    udp_recv(eth_info.eth_100M->udp_pcb, Keti_Eth_UDP_Receiver, eth_info.eth_100M);
    ret_err = udp_bind(eth_info.eth_100M->udp_pcb , &eth_info.eth_100M->udp_pcb->local_ip, eth_info.eth_100M->udp_pcb->local_port);
    eth_info.eth_100M->udp_pcb->netif_idx = netif_get_index(&eth_info.eth_100M->netif);
    eth_info.eth_100M->raw_pcb->netif_idx = netif_get_index(&eth_info.eth_100M->netif);

    eth_info.eth_100M->send_timer = 2000;
    eth_info.eth_100M->rs = Fireware_No_Response_From_ECU;
    Keti_Send_Timer(eth_info.eth_100M);
#if 0
	ip4_addr_t netif_gw;
	IP4_ADDR(&netif_gw, 192, 168, 0, 10);

	raw_recv(eth_info.eth_100M->raw_pcb, Keti_Raw_Receiver, &eth_info.eth_100M->netif);
	raw_bind(eth_info.eth_100M->raw_pcb, &eth_info.eth_100M->src_addr);
#endif
    while (1)
    {
        /* Poll the driver, get any outstanding frames */
    	ethernetif_wait_ipv4_valid(&eth_info.eth_100M->netif, 1);
        //ethernetif_input(&eth_info.eth_1G->netif);

        sys_check_timeouts(); /* Handle all system timeouts for all core protocols */
    }
}
#endif

static Keti_Err_e Keti_i_Ethernet_Interface_Initial(struct Eth_Info_t *eth_info, enum Keti_Eth_Type_e type, const struct Eth_Addr_Info_t *addr_info)
{
    Keti_Err_e ret = 0;
    gpio_pin_config_t gpio_config = {kGPIO_DigitalOutput, 0, kGPIO_NoIntmode};
    switch(type)
    {
        case 0:
        {
            if(eth_info->Eth_100M_On)
            {
                mem_free(eth_info->eth_100M);
            }
            eth_info->eth_100M = mem_malloc((mem_size_t)(sizeof(struct Eth_Addr_Info_t)));
            eth_info->Eth_100M_On = true;
            BOARD_InitEnetPins();
            GPIO_PinInit(GPIO12, 12, &gpio_config);
            GPIO_WritePinOutput(GPIO12, 12, 0);
            SDK_DelayAtLeastUs(10000, CLOCK_GetFreq(kCLOCK_CpuClk));
            GPIO_WritePinOutput(GPIO12, 12, 1);
            SDK_DelayAtLeastUs(6, CLOCK_GetFreq(kCLOCK_CpuClk));

            (void)CLOCK_EnableClock(s_enetClock[ENET_GetInstance(ENET)]);
            ENET_SetSMI(ENET, CLOCK_GetRootClockFreq(kCLOCK_Root_Bus), false);
            g_phy_resource_100M.read  = MDIO_Read_100M;
            g_phy_resource_100M.write = MDIO_Write_100M;
            if(addr_info)
            {
                memcpy(&eth_info->eth_100M->mac_addr, &addr_info->mac_addr, sizeof(u8_t) * 6);
                memcpy(&eth_info->eth_100M->src_addr, &addr_info->src_addr, sizeof(ip4_addr_t));
                memcpy(&eth_info->eth_100M->gw_addr, &addr_info->gw_addr, sizeof(ip4_addr_t));
            }else{
                Keti_s_Ethernet_Interface_Addr_Initial(Ethernet_100M, eth_info->eth_100M);
            }
            eth_info->eth_100M->enet_config.phyAddr = BOARD_ENET0_PHY_ADDRESS;
            eth_info->eth_100M->enet_config.phyOps  = &phyksz8081_ops;
            eth_info->eth_100M->enet_config.phyHandle	= &g_phyHandle_100M;
            eth_info->eth_100M->enet_config.srcClockHz = CLOCK_GetRootClockFreq(kCLOCK_Root_Bus);
            eth_info->eth_100M->enet_config.phyResource = &g_phy_resource_100M;
            memcpy(&eth_info->eth_100M->enet_config.macAddress, &eth_info->eth_100M->mac_addr, sizeof(u8_t) * 6);
            ip4_addr_t netif_netmask;
            IP4_ADDR(&netif_netmask, 255, 255, 255, 255);

            netif_add(&eth_info->eth_100M->netif, &eth_info->eth_100M->src_addr, &netif_netmask, &eth_info->eth_100M->gw_addr, &eth_info->eth_100M->enet_config, ethernetif0_init, ethernet_input);
        	netif_set_default(&eth_info->eth_100M->netif);
        	netif_set_up(&eth_info->eth_100M->netif);
        	while (ethernetif_wait_linkup(&eth_info->eth_100M->netif, 5000) != ERR_OK)
        	{
        		PRINTF("PHY Auto-negotiation failed. Please check the cable connection and link partner setting.\n\r");
        	}
            break;
        }
        case 1:
        {
            if(eth_info->Eth_1G_On == 1)
            {
            	PRINTF("eth_info->Eth_1G_On:%d\n\r", eth_info->Eth_1G_On);
                mem_free(eth_info->eth_1G);
            }
            eth_info->eth_1G = mem_malloc((mem_size_t)(sizeof(struct Eth_Addr_Info_t)));
            memset(eth_info->eth_1G, 0x00, sizeof(struct Eth_Addr_Info_t));
            eth_info->Eth_1G_On = true;

            BOARD_InitEnet1GPins();
            GPIO_PinInit(GPIO11, 14, &gpio_config);
            GPIO_WritePinOutput(GPIO11, 14, 0);
            SDK_DelayAtLeastUs(10000, CLOCK_GetFreq(kCLOCK_CpuClk));
            GPIO_WritePinOutput(GPIO11, 14, 1);
            SDK_DelayAtLeastUs(30000, CLOCK_GetFreq(kCLOCK_CpuClk));

            EnableIRQ(ENET_1G_MAC0_Tx_Rx_1_IRQn);
            EnableIRQ(ENET_1G_MAC0_Tx_Rx_2_IRQn);

            (void)CLOCK_EnableClock(s_enetClock[ENET_GetInstance(ENET_1G)]);
            ENET_SetSMI(ENET_1G, CLOCK_GetRootClockFreq(kCLOCK_Root_Bus), false);
            g_phy_resource_1G.read  = MDIO_Read_1G;
            g_phy_resource_1G.write = MDIO_Write_1G;
            if(addr_info)
            {
                memcpy(&eth_info->eth_1G->mac_addr, &addr_info->mac_addr, sizeof(u8_t) * 6);
                memcpy(&eth_info->eth_1G->src_addr, &addr_info->src_addr, sizeof(ip4_addr_t));
                memcpy(&eth_info->eth_1G->gw_addr, &addr_info->gw_addr, sizeof(ip4_addr_t));
            }else{
            	Keti_s_Ethernet_Interface_Addr_Initial(Ethernet_1G, eth_info->eth_1G);
            }
            eth_info->eth_1G->enet_config.phyAddr = BOARD_ENET1_PHY_ADDRESS;
            eth_info->eth_1G->enet_config.phyOps  = &phyrtl8211f_ops;
            eth_info->eth_1G->enet_config.phyHandle	= &g_phyHandle_1G;
            eth_info->eth_1G->enet_config.srcClockHz = CLOCK_GetRootClockFreq(kCLOCK_Root_Bus);
            eth_info->eth_1G->enet_config.phyResource = &g_phy_resource_1G;
            memcpy(&eth_info->eth_100M->enet_config.macAddress, &eth_info->eth_1G->mac_addr, sizeof(u8_t) * 6);
            ip4_addr_t netif_netmask;
            IP4_ADDR(&netif_netmask, 255, 255, 255, 255);

            netif_add(&eth_info->eth_1G->netif, &eth_info->eth_1G->src_addr, &netif_netmask, &eth_info->eth_1G->gw_addr, &eth_info->eth_1G->enet_config, ethernetif1_init, ethernet_input);
        	netif_set_default(&eth_info->eth_1G->netif);
        	netif_set_up(&eth_info->eth_1G->netif);
        	while (ethernetif_wait_linkup(&eth_info->eth_1G->netif, 5000) != ERR_OK)
        	{
        		PRINTF("PHY Auto-negotiation failed. Please check the cable connection and link partner setting.\n\r");
        	}
            break;
        }
        default: break;
    }

    return ret;
}

static Keti_Err_e Keti_s_Ethernet_Interface_Addr_Initial(enum Keti_Eth_Type_e type, struct Eth_Addr_Info_t *eth)
{
	Keti_Err_e ret = 0;

    switch(type)
    {
        default: return ret;break;
        case Ethernet_100M:
        {   
            (void)SILICONID_ConvertToMacAddr(&eth->mac_addr);
            eth->mac_addr[5] = 0x10;
            DEFAULT_ETH_100M_ADDR(&eth->src_addr);
            DEFAULT_ETH_GATEWAY(&eth->gw_addr);
            break;
        }
        case Ethernet_1G:
        {
            (void)SILICONID_ConvertToMacAddr(&eth->mac_addr);
            eth->mac_addr[5] = 0x20;
            DEFAULT_ETH_1G_ADDR(&eth->src_addr);
            DEFAULT_ETH_GATEWAY(&eth->gw_addr);
            break;
        }
    }
    return ret;
}

static status_t MDIO_Write_100M(uint8_t phyAddr, uint8_t regAddr, uint16_t data)
{
    return ENET_MDIOWrite(ENET, phyAddr, regAddr, data);
}
static status_t MDIO_Read_100M(uint8_t phyAddr, uint8_t regAddr, uint16_t *pData)
{
    return ENET_MDIORead(ENET, phyAddr, regAddr, pData);
}
static status_t MDIO_Write_1G(uint8_t phyAddr, uint8_t regAddr, uint16_t data)
{
    return ENET_MDIOWrite(ENET_1G, phyAddr, regAddr, data);
}
static status_t MDIO_Read_1G(uint8_t phyAddr, uint8_t regAddr, uint16_t *pData)
{
    return ENET_MDIORead(ENET_1G, phyAddr, regAddr, pData);
}

static void Keti_Send_Timer(void *arg)
{
  struct Eth_Addr_Info_t *info = (struct Eth_Addr_Info_t*)arg;
  struct udp_pcb *pcb = info->udp_pcb;
  struct raw_pcb *raw_pcb = info->raw_pcb;
  u32_t timer = info->send_timer;
  info->send_buf = test_dump;
  switch(info->rs)
  {
  	  default:break;
  	  case Fireware_No_Response_From_ECU:
  	  case Model_No_Response_From_ECU:
	  {
		  Keti_Err_e err_ret = Keit_Eth_UDP_Sender(pcb, raw_pcb, info->send_buf, 24);
		  break;
	  }
  	  case Fireware_Response_Info_From_ECU:
  	  case Model_Response_Info_From_ECU:
      {
		  info->rs++;
		  break;
	  }
  	  case Fireware_Wait_Indication_From_ECU:
  	  case Model_Wait_Indication_From_ECU:
	  {
		  Keti_Err_e err_ret = Keit_Eth_UDP_Sender(pcb, raw_pcb, info->send_buf, 24);
		  break;
	  }
  }

  sys_timeout(timer, Keti_Send_Timer, info);

}

static Keti_Err_e Keit_Eth_UDP_Sender(struct udp_pcb *pcb, struct raw_pcb *raw_pcb, u8_t *data, u16_t data_len)
{
	struct pbuf *p;
	err_t err_ret;
	size_t udp_size = sizeof(struct udp_hdr) + data_len;
	p = pbuf_alloc(PBUF_IP, (u16_t)udp_size, PBUF_RAM);
	struct udp_hdr *udphdr = (struct udp_hdr*)p->payload;
	udphdr->src = lwip_htons(pcb->local_port);
	udphdr->dest = lwip_htons(pcb->remote_port);
	udphdr->len = lwip_htons(sizeof(struct udp_hdr) + data_len);
	udphdr->chksum = 0x0000;
	u16_t udpchksum = ip_chksum_pseudo(p, IP_PROTO_UDP, p->tot_len, (ip_addr_t*)&pcb->local_ip, (ip_addr_t*)&pcb->remote_ip);
	if (udpchksum == 0x0000) {
	  udpchksum = 0xffff;
	}
	udphdr->chksum = udpchksum;
	u8_t *payload = (u8_t*)(udphdr + sizeof(struct udp_hdr)/8);
	memcpy(payload, data, data_len);
	err_ret = raw_sendto(raw_pcb, p, (ip_addr_t*)&pcb->remote_ip);
	pbuf_free(p);
	return ERR_OK;
}

static void Keti_Eth_UDP_Receiver(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port)
{
	struct Eth_Addr_Info_t *info = (struct Eth_Addr_Info_t*)arg;
    struct ip_hdr *iphdr;
	struct udp_hdr *udphdr;
	u8_t *udp_payload;
	size_t udp_payload_len;
	u32_t *pointer_now;
    
	struct netif *inp = netif_get_by_index(pcb->netif_idx);
	udp_input(p, inp);
    
	PRINTF("100M Eth recv_printer:%p, payload_len:%d\n\r", p, p->len);
	for(int i = 0; i < p->len; i++)
	{
	  PRINTF("%02X", ((u8_t *)p->payload)[i]);
	}
	PRINTF("\n\r");
    switch(info->rs)
    {
        default:break;
        case Fireware_No_Response_From_ECU:
        case Model_No_Response_From_ECU:
        {
            if(strncmp(p->payload, info->send_buf, p->len) == 0){
                PRINTF("RESPONED_INFO_FROM_ECU!\n\r");
                info->rs++;
            } 
            break;
        }
        case Fireware_Response_Info_From_ECU:
        case Model_Response_Info_From_ECU:
        case Fireware_Wait_Indication_From_ECU:
        case Model_Wait_Indication_From_ECU:
        {
            break;
        }
    } 
}


static u8_t Keti_Raw_Receiver(void *arg, struct raw_pcb *pcb, struct pbuf *p, const ip_addr_t *addr)
{
  struct icmp_echo_hdr *iecho;
  LWIP_UNUSED_ARG(arg);
  LWIP_UNUSED_ARG(pcb);
  LWIP_UNUSED_ARG(addr);
  LWIP_ASSERT("p != NULL", p != NULL);
  PRINTF("100M Eth recv_printer:%p, payload_len:%d\n\r", p, p->len);
  for(int i = 0; i < p->len; i++)
  {
	  PRINTF("%02X", ((u8_t *)p->payload)[i]);
  }
  PRINTF("\n\r");

#if 0
  if ((p->tot_len >= (PBUF_IP_HLEN + sizeof(struct icmp_echo_hdr))) &&
      pbuf_remove_header(p, PBUF_IP_HLEN) == 0) {
    iecho = (struct icmp_echo_hdr *)p->payload;

    if ((iecho->id == PING_ID) && (iecho->seqno == lwip_htons(ping_seq_num))) {
      LWIP_DEBUGF( PING_DEBUG, ("ping: recv "));
      ip_addr_debug_print(PING_DEBUG, addr);
      LWIP_DEBUGF( PING_DEBUG, (" %"U32_F" ms\n", (sys_now()-ping_time)));

      /* do some ping result processing */
      PING_RESULT(1);
      pbuf_free(p);
      return 1; /* eat the packet */
    }
    /* not eaten, restore original packet */
    /* Changed to the "_force" version because of LPC zerocopy pbufs */
    pbuf_add_header_force(p, PBUF_IP_HLEN);
  }
#endif

  return 0; /* don't eat the packet */
}
