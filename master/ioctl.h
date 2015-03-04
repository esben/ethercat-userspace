/******************************************************************************
 *
 *  $Id: ioctl.h,v c4afc5fede19 2011/10/24 08:49:27 fp $
 *
 *  Copyright (C) 2006-2008  Florian Pose, Ingenieurgemeinschaft IgH
 *
 *  This file is part of the IgH EtherCAT Master.
 *
 *  The IgH EtherCAT Master is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License version 2, as
 *  published by the Free Software Foundation.
 *
 *  The IgH EtherCAT Master is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
 *  Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with the IgH EtherCAT Master; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 *  ---
 *
 *  The license mentioned above concerns the source code only. Using the
 *  EtherCAT technology and brand is only permitted in compliance with the
 *  industrial property and similar rights of Beckhoff Automation GmbH.
 *
 *****************************************************************************/

/**
   \file
   EtherCAT master character device IOCTL commands.
*/

/*****************************************************************************/

#ifndef __EC_IOCTL_H__
#define __EC_IOCTL_H__

#include <linux/ioctl.h>

#include "globals.h"

/*****************************************************************************/

/** \cond */

#define EC_IOCTL_TYPE 0xa4

#define EC_IO(nr)           _IO(EC_IOCTL_TYPE, nr)
#define EC_IOR(nr, type)   _IOR(EC_IOCTL_TYPE, nr, type)
#define EC_IOW(nr, type)   _IOW(EC_IOCTL_TYPE, nr, type)
#define EC_IOWR(nr, type) _IOWR(EC_IOCTL_TYPE, nr, type)

/** EtherCAT master ioctl() version magic.
 *
 * Increment this when changing the ioctl interface!
 */
#define EC_IOCTL_VERSION_MAGIC 13

// Command-line tool
#define EC_IOCTL_MODULE                EC_IOR(0x00, ec_ioctl_module_t)
#define EC_IOCTL_MASTER                EC_IOR(0x01, ec_ioctl_master_t)
#define EC_IOCTL_SLAVE                EC_IOWR(0x02, ec_ioctl_slave_t)
#define EC_IOCTL_SLAVE_SYNC           EC_IOWR(0x03, ec_ioctl_slave_sync_t)
#define EC_IOCTL_SLAVE_SYNC_PDO       EC_IOWR(0x04, ec_ioctl_slave_sync_pdo_t)
#define EC_IOCTL_SLAVE_SYNC_PDO_ENTRY EC_IOWR(0x05, ec_ioctl_slave_sync_pdo_entry_t)
#define EC_IOCTL_DOMAIN               EC_IOWR(0x06, ec_ioctl_domain_t)
#define EC_IOCTL_DOMAIN_FMMU          EC_IOWR(0x07, ec_ioctl_domain_fmmu_t)
#define EC_IOCTL_DOMAIN_DATA          EC_IOWR(0x08, ec_ioctl_domain_data_t)
#define EC_IOCTL_MASTER_DEBUG           EC_IO(0x09)
#define EC_IOCTL_MASTER_RESCAN          EC_IO(0x0a)
#define EC_IOCTL_SLAVE_STATE           EC_IOW(0x0b, ec_ioctl_slave_state_t)
#define EC_IOCTL_SLAVE_SDO            EC_IOWR(0x0c, ec_ioctl_slave_sdo_t)
#define EC_IOCTL_SLAVE_SDO_ENTRY      EC_IOWR(0x0d, ec_ioctl_slave_sdo_entry_t)
#define EC_IOCTL_SLAVE_SDO_UPLOAD     EC_IOWR(0x0e, ec_ioctl_slave_sdo_upload_t)
#define EC_IOCTL_SLAVE_SDO_DOWNLOAD   EC_IOWR(0x0f, ec_ioctl_slave_sdo_download_t)
#define EC_IOCTL_SLAVE_SII_READ       EC_IOWR(0x10, ec_ioctl_slave_sii_t)
#define EC_IOCTL_SLAVE_SII_WRITE       EC_IOW(0x11, ec_ioctl_slave_sii_t)
#define EC_IOCTL_SLAVE_REG_READ       EC_IOWR(0x12, ec_ioctl_slave_reg_t)
#define EC_IOCTL_SLAVE_REG_WRITE       EC_IOW(0x13, ec_ioctl_slave_reg_t)
#define EC_IOCTL_SLAVE_FOE_READ       EC_IOWR(0x14, ec_ioctl_slave_foe_t)
#define EC_IOCTL_SLAVE_FOE_WRITE       EC_IOW(0x15, ec_ioctl_slave_foe_t)
#define EC_IOCTL_SLAVE_SOE_READ       EC_IOWR(0x16, ec_ioctl_slave_soe_read_t)
#define EC_IOCTL_SLAVE_SOE_WRITE      EC_IOWR(0x17, ec_ioctl_slave_soe_write_t)
#define EC_IOCTL_CONFIG               EC_IOWR(0x18, ec_ioctl_config_t)
#define EC_IOCTL_CONFIG_PDO           EC_IOWR(0x19, ec_ioctl_config_pdo_t)
#define EC_IOCTL_CONFIG_PDO_ENTRY     EC_IOWR(0x1a, ec_ioctl_config_pdo_entry_t)
#define EC_IOCTL_CONFIG_SDO           EC_IOWR(0x1b, ec_ioctl_config_sdo_t)
#define EC_IOCTL_CONFIG_IDN           EC_IOWR(0x1c, ec_ioctl_config_idn_t)
#ifdef EC_EOE
#define EC_IOCTL_EOE_HANDLER          EC_IOWR(0x1d, ec_ioctl_eoe_handler_t)
#endif

// Application interface
#define EC_IOCTL_REQUEST                EC_IO(0x1e)
#define EC_IOCTL_CREATE_DOMAIN          EC_IO(0x1f)
#define EC_IOCTL_CREATE_SLAVE_CONFIG  EC_IOWR(0x20, ec_ioctl_config_t)
#define EC_IOCTL_ACTIVATE              EC_IOR(0x21, size_t)
#define EC_IOCTL_DEACTIVATE             EC_IO(0x22)
#define EC_IOCTL_SEND                   EC_IO(0x23)
#define EC_IOCTL_RECEIVE                EC_IO(0x24)
#define EC_IOCTL_MASTER_STATE          EC_IOR(0x25, ec_master_state_t)
#define EC_IOCTL_APP_TIME              EC_IOW(0x26, ec_ioctl_app_time_t)
#define EC_IOCTL_SYNC_REF               EC_IO(0x27)
#define EC_IOCTL_SYNC_SLAVES            EC_IO(0x28)
#define EC_IOCTL_SYNC_MON_QUEUE         EC_IO(0x29)
#define EC_IOCTL_SYNC_MON_PROCESS      EC_IOR(0x2a, uint32_t)
#define EC_IOCTL_RESET                  EC_IO(0x2b)
#define EC_IOCTL_SC_SYNC               EC_IOW(0x2c, ec_ioctl_config_t)
#define EC_IOCTL_SC_WATCHDOG           EC_IOW(0x2d, ec_ioctl_config_t)
#define EC_IOCTL_SC_ADD_PDO            EC_IOW(0x2e, ec_ioctl_config_pdo_t)
#define EC_IOCTL_SC_CLEAR_PDOS         EC_IOW(0x2f, ec_ioctl_config_pdo_t)
#define EC_IOCTL_SC_ADD_ENTRY          EC_IOW(0x30, ec_ioctl_add_pdo_entry_t)
#define EC_IOCTL_SC_CLEAR_ENTRIES      EC_IOW(0x31, ec_ioctl_config_pdo_t)
#define EC_IOCTL_SC_REG_PDO_ENTRY     EC_IOWR(0x32, ec_ioctl_reg_pdo_entry_t)
#define EC_IOCTL_SC_DC                 EC_IOW(0x33, ec_ioctl_config_t)
#define EC_IOCTL_SC_SDO                EC_IOW(0x34, ec_ioctl_sc_sdo_t)
#define EC_IOCTL_SC_SDO_REQUEST       EC_IOWR(0x35, ec_ioctl_sdo_request_t)
#define EC_IOCTL_SC_VOE               EC_IOWR(0x36, ec_ioctl_voe_t)
#define EC_IOCTL_SC_STATE             EC_IOWR(0x37, ec_ioctl_sc_state_t)
#define EC_IOCTL_SC_IDN                EC_IOW(0x38, ec_ioctl_sc_idn_t)
#define EC_IOCTL_DOMAIN_OFFSET          EC_IO(0x39)
#define EC_IOCTL_DOMAIN_PROCESS         EC_IO(0x3a)
#define EC_IOCTL_DOMAIN_QUEUE           EC_IO(0x3b)
#define EC_IOCTL_DOMAIN_STATE         EC_IOWR(0x3c, ec_ioctl_domain_state_t)
#define EC_IOCTL_SDO_REQUEST_TIMEOUT  EC_IOWR(0x3d, ec_ioctl_sdo_request_t)
#define EC_IOCTL_SDO_REQUEST_STATE    EC_IOWR(0x3e, ec_ioctl_sdo_request_t)
#define EC_IOCTL_SDO_REQUEST_READ     EC_IOWR(0x3f, ec_ioctl_sdo_request_t)
#define EC_IOCTL_SDO_REQUEST_WRITE    EC_IOWR(0x40, ec_ioctl_sdo_request_t)
#define EC_IOCTL_SDO_REQUEST_DATA     EC_IOWR(0x41, ec_ioctl_sdo_request_t)
#define EC_IOCTL_VOE_SEND_HEADER       EC_IOW(0x42, ec_ioctl_voe_t)
#define EC_IOCTL_VOE_REC_HEADER       EC_IOWR(0x43, ec_ioctl_voe_t)
#define EC_IOCTL_VOE_READ              EC_IOW(0x44, ec_ioctl_voe_t)
#define EC_IOCTL_VOE_READ_NOSYNC       EC_IOW(0x45, ec_ioctl_voe_t)
#define EC_IOCTL_VOE_WRITE            EC_IOWR(0x46, ec_ioctl_voe_t)
#define EC_IOCTL_VOE_EXEC             EC_IOWR(0x47, ec_ioctl_voe_t)
#define EC_IOCTL_VOE_DATA             EC_IOWR(0x48, ec_ioctl_voe_t)
#define EC_IOCTL_SET_SEND_INTERVAL     EC_IOW(0x49, size_t)

/*****************************************************************************/

#define EC_IOCTL_STRING_SIZE 64

/*****************************************************************************/

typedef struct {
    uint32_t ioctl_version_magic;
    uint32_t master_count;
} ec_ioctl_module_t;

/*****************************************************************************/

typedef struct {
    uint32_t slave_count;
    uint32_t config_count;
    uint32_t domain_count;
#ifdef EC_EOE
    uint32_t eoe_handler_count;
#endif
    uint8_t phase;
    uint8_t active;
    uint8_t scan_busy;
    struct ec_ioctl_device {
        uint8_t address[6];
        uint8_t attached;
        uint8_t link_state;
        uint64_t tx_count;
        uint64_t rx_count;
        uint64_t tx_bytes;
        uint64_t tx_errors;
        uint32_t tx_frame_rates[EC_RATE_COUNT];
        uint32_t tx_byte_rates[EC_RATE_COUNT];
        int32_t loss_rates[EC_RATE_COUNT];
    } devices[2];
    uint64_t app_time;
    uint16_t ref_clock;
} ec_ioctl_master_t;

/*****************************************************************************/

typedef struct {
    // input
    uint16_t position;

    // outputs
    uint32_t vendor_id;
    uint32_t product_code;
    uint32_t revision_number;
    uint32_t serial_number;
    uint16_t alias;
    uint16_t boot_rx_mailbox_offset;
    uint16_t boot_rx_mailbox_size;
    uint16_t boot_tx_mailbox_offset;
    uint16_t boot_tx_mailbox_size;
    uint16_t std_rx_mailbox_offset;
    uint16_t std_rx_mailbox_size;
    uint16_t std_tx_mailbox_offset;
    uint16_t std_tx_mailbox_size;
    uint16_t mailbox_protocols;
    uint8_t has_general_category;
    ec_sii_coe_details_t coe_details;
    ec_sii_general_flags_t general_flags;
    int16_t current_on_ebus;
    struct {
        ec_slave_port_desc_t desc;
        ec_slave_port_link_t link;
        uint32_t receive_time;
        uint16_t next_slave;
        uint32_t delay_to_next_dc;
    } ports[EC_MAX_PORTS];
    uint8_t fmmu_bit;
    uint8_t dc_supported;
    ec_slave_dc_range_t dc_range;
    uint8_t has_dc_system_time;
    uint32_t transmission_delay;
    uint8_t al_state;
    uint8_t sdo_dictionary_fetched;
    uint8_t error_flag;
    uint8_t sync_count;
    uint16_t sdo_count;
    uint32_t sii_nwords;
    char group[EC_IOCTL_STRING_SIZE];
    char image[EC_IOCTL_STRING_SIZE];
    char order[EC_IOCTL_STRING_SIZE];
    char name[EC_IOCTL_STRING_SIZE];
} ec_ioctl_slave_t;

/*****************************************************************************/

typedef struct {
    // inputs
    uint16_t slave_position;
    uint32_t sync_index;

    // outputs
    uint16_t physical_start_address;
    uint16_t default_size;
    uint8_t control_register;
    uint8_t enable;
    uint8_t pdo_count;
} ec_ioctl_slave_sync_t;

/*****************************************************************************/

typedef struct {
    // inputs
    uint16_t slave_position;
    uint32_t sync_index;
    uint32_t pdo_pos;

    // outputs
    uint16_t index;
    uint8_t entry_count;
    int8_t name[EC_IOCTL_STRING_SIZE];
} ec_ioctl_slave_sync_pdo_t;

/*****************************************************************************/

typedef struct {
    // inputs
    uint16_t slave_position;
    uint32_t sync_index;
    uint32_t pdo_pos;
    uint32_t entry_pos;

    // outputs
    uint16_t index;
    uint8_t subindex;
    uint8_t bit_length;
    int8_t name[EC_IOCTL_STRING_SIZE];
} ec_ioctl_slave_sync_pdo_entry_t;

/*****************************************************************************/

typedef struct {
    // inputs
    uint32_t index;

    // outputs
    uint32_t data_size;
    uint32_t logical_base_address;
    uint16_t working_counter;
    uint16_t expected_working_counter;
    uint32_t fmmu_count;
} ec_ioctl_domain_t;

/*****************************************************************************/

typedef struct {
    // inputs
    uint32_t domain_index;
    uint32_t fmmu_index;

    // outputs
    uint16_t slave_config_alias;
    uint16_t slave_config_position;
    uint8_t sync_index;
    ec_direction_t dir;
    uint32_t logical_address;
    uint32_t data_size;
} ec_ioctl_domain_fmmu_t;

/*****************************************************************************/

typedef struct {
    // inputs
    uint32_t domain_index;
    uint32_t data_size;
    uint8_t *target;
} ec_ioctl_domain_data_t;

/*****************************************************************************/

typedef struct {
    // inputs
    uint16_t slave_position;
    uint8_t al_state;
} ec_ioctl_slave_state_t;

/*****************************************************************************/

typedef struct {
    // inputs
    uint16_t slave_position;
    uint16_t sdo_position;

    // outputs
    uint16_t sdo_index;
    uint8_t max_subindex;
    int8_t name[EC_IOCTL_STRING_SIZE];
} ec_ioctl_slave_sdo_t;

/*****************************************************************************/

typedef struct {
    // inputs
    uint16_t slave_position;
    int sdo_spec; // positive: index, negative: list position
    uint8_t sdo_entry_subindex;

    // outputs
    uint16_t data_type;
    uint16_t bit_length;
    uint8_t read_access[EC_SDO_ENTRY_ACCESS_COUNT];
    uint8_t write_access[EC_SDO_ENTRY_ACCESS_COUNT];
    int8_t description[EC_IOCTL_STRING_SIZE];
} ec_ioctl_slave_sdo_entry_t;

/*****************************************************************************/

typedef struct {
    // inputs
    uint16_t slave_position;
    uint16_t sdo_index;
    uint8_t sdo_entry_subindex;
    uint32_t target_size;
    uint8_t *target;

    // outputs
    uint32_t data_size;
    uint32_t abort_code;
} ec_ioctl_slave_sdo_upload_t;

/*****************************************************************************/

typedef struct {
    // inputs
    uint16_t slave_position;
    uint16_t sdo_index;
    uint8_t sdo_entry_subindex;
    uint8_t complete_access;
    uint32_t data_size;
    const uint8_t *data;

    // outputs
    uint32_t abort_code;
} ec_ioctl_slave_sdo_download_t;

/*****************************************************************************/

typedef struct {
    // inputs
    uint16_t slave_position;
    uint16_t offset;
    uint32_t nwords;
    uint16_t *words;
} ec_ioctl_slave_sii_t;

/*****************************************************************************/

typedef struct {
    // inputs
    uint16_t slave_position;
    uint16_t offset;
    uint16_t length;
    uint8_t *data;
} ec_ioctl_slave_reg_t;

/*****************************************************************************/

typedef struct {
    // inputs
    uint16_t slave_position;
    uint16_t offset;
    uint32_t buffer_size;
    uint8_t *buffer;

    // outputs
    uint32_t data_size;
    uint32_t result;
    uint32_t error_code;
    char file_name[32];
} ec_ioctl_slave_foe_t;

/*****************************************************************************/

typedef struct {
    // inputs
    uint16_t slave_position;
    uint8_t drive_no;
    uint16_t idn;
    uint32_t mem_size;
    uint8_t *data;

    // outputs
    size_t data_size;
    uint16_t error_code;
} ec_ioctl_slave_soe_read_t;

/*****************************************************************************/

typedef struct {
    // inputs
    uint16_t slave_position;
    uint8_t drive_no;
    uint16_t idn;
    size_t data_size;
    uint8_t *data;

    // outputs
    uint16_t error_code;
} ec_ioctl_slave_soe_write_t;

/*****************************************************************************/

typedef struct {
    // inputs
    uint32_t config_index;

    // outputs
    uint16_t alias;
    uint16_t position;
    uint32_t vendor_id;
    uint32_t product_code;
    struct {
        ec_direction_t dir;
        ec_watchdog_mode_t watchdog_mode;
        uint32_t pdo_count;
        uint8_t config_this;
    } syncs[EC_MAX_SYNC_MANAGERS];
    uint16_t watchdog_divider;
    uint16_t watchdog_intervals;
    uint32_t sdo_count;
    uint32_t idn_count;
    int32_t slave_position;
    uint16_t dc_assign_activate;
    ec_sync_signal_t dc_sync[EC_SYNC_SIGNAL_COUNT];
} ec_ioctl_config_t;

/*****************************************************************************/

typedef struct {
    // inputs
    uint32_t config_index;
    uint8_t sync_index;
    uint16_t pdo_pos;

    // outputs
    uint16_t index;
    uint8_t entry_count;
    int8_t name[EC_IOCTL_STRING_SIZE];
} ec_ioctl_config_pdo_t;

/*****************************************************************************/

typedef struct {
    // inputs
    uint32_t config_index;
    uint8_t sync_index;
    uint16_t pdo_pos;
    uint8_t entry_pos;

    // outputs
    uint16_t index;
    uint8_t subindex;
    uint8_t bit_length;
    int8_t name[EC_IOCTL_STRING_SIZE];
} ec_ioctl_config_pdo_entry_t;

/*****************************************************************************/

/** Maximum size for displayed SDO data.
 * \todo Make this dynamic.
 */
#define EC_MAX_SDO_DATA_SIZE 1024

typedef struct {
    // inputs
    uint32_t config_index;
    uint32_t sdo_pos;

    // outputs
    uint16_t index;
    uint8_t subindex;
    uint32_t size;
    uint8_t data[EC_MAX_SDO_DATA_SIZE];
} ec_ioctl_config_sdo_t;

/*****************************************************************************/

/** Maximum size for displayed IDN data.
 * \todo Make this dynamic.
 */
#define EC_MAX_IDN_DATA_SIZE 1024

typedef struct {
    // inputs
    uint32_t config_index;
    uint32_t idn_pos;

    // outputs
    uint8_t drive_no;
    uint16_t idn;
    ec_al_state_t state;
    size_t size;
    uint8_t data[EC_MAX_IDN_DATA_SIZE];
} ec_ioctl_config_idn_t;

/*****************************************************************************/

#ifdef EC_EOE

typedef struct {
    // input
    uint16_t eoe_index;

    // outputs
    char name[EC_DATAGRAM_NAME_SIZE];
    uint16_t slave_position;
    uint8_t open;
    uint32_t rx_bytes;
    uint32_t rx_rate;
    uint32_t tx_bytes;
    uint32_t tx_rate;
    uint32_t tx_queued_frames;
    uint32_t tx_queue_size;
} ec_ioctl_eoe_handler_t;

#endif

/*****************************************************************************/

typedef struct {
    // inputs
    uint32_t config_index;
    uint16_t pdo_index;
    uint16_t entry_index;
    uint8_t entry_subindex;
    uint8_t entry_bit_length;
} ec_ioctl_add_pdo_entry_t;

/*****************************************************************************/

typedef struct {
    // inputs
    uint32_t config_index;
    uint16_t entry_index;
    uint8_t entry_subindex;
    uint32_t domain_index;
    
    // outputs
    unsigned int bit_position;
} ec_ioctl_reg_pdo_entry_t;

/*****************************************************************************/

typedef struct {
    // inputs
    uint32_t config_index;
    uint16_t index;
    uint8_t subindex;
    const uint8_t *data;
    size_t size;
    uint8_t complete_access;
} ec_ioctl_sc_sdo_t;

/*****************************************************************************/

typedef struct {
    // inputs
    uint32_t config_index;

    // outputs
    ec_slave_config_state_t *state;
} ec_ioctl_sc_state_t;

/*****************************************************************************/

typedef struct {
    // inputs
    uint32_t config_index;
    uint8_t drive_no;
    uint16_t idn;
    ec_al_state_t al_state;
    const uint8_t *data;
    size_t size;
} ec_ioctl_sc_idn_t;

/*****************************************************************************/

typedef struct {
    // inputs
    uint32_t domain_index;

    // outputs
    ec_domain_state_t *state;
} ec_ioctl_domain_state_t;

/*****************************************************************************/

typedef struct {
    // inputs
    uint32_t config_index;

    // inputs/outputs
    uint32_t request_index;
    uint16_t sdo_index;
    uint8_t sdo_subindex;
    size_t size;
    uint8_t *data;
    uint32_t timeout;
    ec_request_state_t state;
} ec_ioctl_sdo_request_t;

/*****************************************************************************/

typedef struct {
    // inputs
    uint32_t config_index;

    // inputs/outputs
    uint32_t voe_index;
    uint32_t *vendor_id;
    uint16_t *vendor_type;
    size_t size;
    uint8_t *data;
    ec_request_state_t state;
} ec_ioctl_voe_t;

/*****************************************************************************/

typedef struct {
    // inputs
    uint64_t app_time;
} ec_ioctl_app_time_t;

/*****************************************************************************/

/** \endcond */

#ifdef EC_MASTER_IN_USERSPACE

/* Emulated ioctl via TCP connection for userspace master */

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Port for the first master. The following masters use subsequent ports. */
#define ECRT_PORT_BASE 0x88A4

#define EC_MAX_IOCTL_DATA_SIZE 0x1000

static inline ssize_t read_all(int fd, void *data, size_t size)
{
  size_t n = 0;
  while (n < size) {
      ssize_t r = read(fd, (char *)data + n, size - n);
      if (r == 0) {
          errno = EPIPE;
          return -1;
      }
      if (r < 0)
          return r;
      n += r;
  }
  return size;
}

static inline ssize_t send_all(int fd, const void *data, size_t size, int has_more)
{
  size_t n = 0;
  while (n < size) {
      ssize_t r = send(fd, (const char *)data + n, size - n,
                       has_more ? MSG_MORE : 0);
      if (r == 0) {
          errno = EPIPE;
          return -1;
      }
      if (r < 0)
          return r;
      n += r;
  }
  return size;
}

static inline struct addrinfo *gai(const char *host, int port, int flags)
{
    char service[0x40];
    snprintf(service, sizeof(service), "%i", port);
    struct addrinfo hints, *r = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_ADDRCONFIG | flags;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    int err = getaddrinfo(host, service, &hints, &r);
    if (err) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
        return NULL;
    }
    if (!r)
        fprintf(stderr, "Address not found\n");
    return r;
}

#ifdef __KERNEL__

struct socket_list {
    struct list_head list;
    int socket;
};

static inline void ioctl_server_open(int master_index, struct list_head *sockets)
{
    struct addrinfo *a = gai(NULL, ECRT_PORT_BASE + master_index, AI_PASSIVE), *p;
    for (p = a; p; p = p->ai_next) {
        int r = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (r < 0)
            continue;
        int on = 1;
        struct socket_list *s;
        if ((p->ai_family != AF_INET6 || setsockopt (r, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof (on)) == 0)
            && setsockopt(r, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on)) == 0
            && bind(r, p->ai_addr, p->ai_addrlen) == 0
            && listen(r, 16) == 0
            && (s = kmalloc(sizeof(struct socket_list), GFP_KERNEL))) {
            s->socket = r;
            list_add_tail(&s->list, sockets);
        } else {
            close(r);
        }
    }
    freeaddrinfo(a);
}

#endif

static inline int ioctl_client_open(int master_index, const char *host)
{
    int r = -1;
    struct addrinfo *a = gai(host, ECRT_PORT_BASE + master_index, 0), *p;
    for (p = a; r < 0 && p; p = p->ai_next) {
        r = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (r >= 0 && connect(r, p->ai_addr, p->ai_addrlen) < 0) {
            close(r);
            r = -1;
        }
    }
    freeaddrinfo(a);
    return r;
}

typedef unsigned fmode_t;

#define FMODE_WRITE 2

struct file
{
    fmode_t f_mode;
    void *private_data;
    void *data_from_user, *data_to_user;
    size_t data_to_user_size;
};

struct ioctl_command_block
{
    int32_t cmd, data_size;
    uint32_t data_from_user_size, data_to_user_size;
};

struct ioctl_reply_block
{
    int32_t result;
    uint32_t data_to_user_size;
};

static inline int ioctl_server(int fd, long (*ioctl_func) (struct file *filp, unsigned int cmd, unsigned long arg), struct file *filp)
{
    struct ioctl_command_block b;
    if (read_all(fd, &b, sizeof(b)) < 0)
        return -1;
    unsigned long value = 0;
    int use_value = b.data_size < 0;
    size_t s1 = use_value ? -b.data_size : b.data_size;
    size_t s2 = use_value ? 0 : b.data_size;
    if (s1 > EC_MAX_IOCTL_DATA_SIZE || (use_value && s1 != sizeof(value))) {
        errno = EINVAL;
        return -1;
    }
    void *data = use_value ? &value : alloca(b.data_size);
    if (read_all(fd, data, s1) < 0)
        return -1;
    filp->data_from_user = realloc (filp->data_from_user, b.data_from_user_size);
    filp->data_to_user   = realloc (filp->data_to_user,   b.data_to_user_size);
    filp->data_to_user_size = 0;
    if ((b.data_from_user_size && !filp->data_from_user) ||
        (b.data_to_user_size   && !filp->data_to_user)) {
        errno = ENOMEM;
        return -1;
    }
    if (read_all(fd, filp->data_from_user, b.data_from_user_size) < 0)
        return -1;
    struct ioctl_reply_block r;
    r.result = ioctl_func(filp, b.cmd, use_value ? value : (unsigned long)data);
    r.data_to_user_size = filp->data_to_user_size;
    if (send_all(fd, &r, sizeof(r), s2 || filp->data_to_user_size) < 0
        || send_all(fd, data, s2, r.data_to_user_size) < 0
        || send_all(fd, filp->data_to_user, r.data_to_user_size, 0) < 0)
        return -1;
    return 0;
}

static inline int ioctl_client(int fd, int cmd, ssize_t data_size, void *data)
{
    struct ioctl_command_block b = { cmd, (int32_t)data_size, 0, 0 };

    const void *data_from_user = NULL;
    #define DATA_FROM_USER(CMD, TYPE, DATA, SIZE) \
      if (cmd == (int)(CMD)) { TYPE *d = (TYPE *)data; data_from_user = (DATA); b.data_from_user_size = (SIZE); } else
    DATA_FROM_USER (EC_IOCTL_SLAVE_SDO_DOWNLOAD, ec_ioctl_slave_sdo_download_t, d->data,   d->data_size)
    DATA_FROM_USER (EC_IOCTL_SLAVE_SII_WRITE,    ec_ioctl_slave_sii_t,          d->words,  sizeof(uint16_t) * d->nwords)
    DATA_FROM_USER (EC_IOCTL_SLAVE_REG_WRITE,    ec_ioctl_slave_reg_t,          d->data,   d->length)
    DATA_FROM_USER (EC_IOCTL_SC_SDO,             ec_ioctl_sc_sdo_t,             d->data,   d->size)
    DATA_FROM_USER (EC_IOCTL_SC_IDN,             ec_ioctl_sc_idn_t,             d->data,   d->size)
    DATA_FROM_USER (EC_IOCTL_SDO_REQUEST_WRITE,  ec_ioctl_sdo_request_t,        d->data,   d->size)
    DATA_FROM_USER (EC_IOCTL_VOE_WRITE,          ec_ioctl_voe_t,                d->data,   d->size)
    DATA_FROM_USER (EC_IOCTL_SLAVE_FOE_WRITE,    ec_ioctl_slave_foe_t,          d->buffer, d->buffer_size)
    DATA_FROM_USER (EC_IOCTL_SLAVE_SOE_WRITE,    ec_ioctl_slave_soe_write_t,    d->data,   d->data_size)
    { }
    #undef DATA_FROM_USER

    void *data_to_user = NULL;
    #define DATA_TO_USER(CMD, TYPE, DATA, SIZE) \
      if (cmd == (int)(CMD)) { TYPE *d = (TYPE *)data; data_to_user = (DATA); b.data_to_user_size = (SIZE); } else
    DATA_TO_USER (EC_IOCTL_DOMAIN_DATA,      ec_ioctl_domain_data_t,      d->target, d->data_size)
    DATA_TO_USER (EC_IOCTL_SLAVE_SDO_UPLOAD, ec_ioctl_slave_sdo_upload_t, d->target, d->target_size)
    DATA_TO_USER (EC_IOCTL_SLAVE_SII_READ,   ec_ioctl_slave_sii_t,        d->words,  d->nwords * 2)
    DATA_TO_USER (EC_IOCTL_SLAVE_REG_READ,   ec_ioctl_slave_reg_t,        d->data,   d->length)
    DATA_TO_USER (EC_IOCTL_SC_STATE,         ec_ioctl_sc_state_t,         d->state,  sizeof(ec_slave_config_state_t))
    DATA_TO_USER (EC_IOCTL_DOMAIN_STATE,     ec_ioctl_domain_state_t,     d->state,  sizeof(ec_domain_state_t))
    DATA_TO_USER (EC_IOCTL_SDO_REQUEST_DATA, ec_ioctl_sdo_request_t,      d->data,   d->size)
    DATA_TO_USER (EC_IOCTL_VOE_DATA,         ec_ioctl_voe_t,              d->data,   d->size)
    DATA_TO_USER (EC_IOCTL_SLAVE_FOE_READ,   ec_ioctl_slave_foe_t,        d->buffer, d->data_size)
    DATA_TO_USER (EC_IOCTL_SLAVE_SOE_READ,   ec_ioctl_slave_soe_read_t,   d->data,   d->data_size)
    { }
    #undef DATA_TO_USER

    int use_value = data_size < 0;
    size_t s1 = use_value ? -data_size : data_size;
    size_t s2 = use_value ? 0 : data_size;
    struct ioctl_reply_block r;
    if (send_all(fd, &b, sizeof(b), s1 || b.data_from_user_size) < 0
        || send_all(fd, data, s1, b.data_from_user_size) < 0
        || send_all(fd, data_from_user, b.data_from_user_size, 0) < 0
        || read_all(fd, &r, sizeof(r)) < 0
        || read_all(fd, data, s2) < 0
        || read_all(fd, data_to_user, r.data_to_user_size) < 0)
        return -1;
    if (r.result < 0) {
        errno = -r.result;
        return -1;
    }
    return r.result;
}

#define ioctl_noarg(FD, CMD) (ioctl_client((FD), (CMD), 0, NULL))

static inline int ioctl_value(int fd, int cmd, unsigned long value)
{
  return ioctl_client(fd, cmd, -sizeof(value), &value);
}

#define ioctl_typed(FD, CMD, DATA) (ioctl_client((FD), (CMD), sizeof(*(DATA)), (DATA)))

#else

#define ioctl_noarg(FD, CMD)        (ioctl((FD), (CMD), NULL))
#define ioctl_value(FD, CMD, VALUE) (ioctl((FD), (CMD), (VALUE)))
#define ioctl_typed(FD, CMD, DATA)  (ioctl((FD), (CMD), (DATA)))

#endif

#endif
