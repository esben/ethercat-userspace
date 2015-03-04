/******************************************************************************
 *
 *  $Id: master.c,v fc891656a9fe 2012/01/10 09:11:20 fp $
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
 *  vim: expandtab
 *
 *****************************************************************************/

/**
   \file
   EtherCAT master methods.
*/

/*****************************************************************************/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/version.h>
#include <linux/hrtimer.h>
#include "globals.h"
#include "slave.h"
#include "slave_config.h"
#include "device.h"
#include "datagram.h"
#ifdef EC_EOE
#include "ethernet.h"
#endif
#include "master.h"
#include "mailbox.h"

/*****************************************************************************/

/** Set to 1 to enable external datagram injection debugging.
 */
#define DEBUG_INJECT 0

#ifdef EC_HAVE_CYCLES

/** Frame timeout in cycles.
 */
static cycles_t timeout_cycles;

/** Timeout for external datagram injection [cycles].
 */
static cycles_t ext_injection_timeout_cycles;

#else

/** Frame timeout in jiffies.
 */
static unsigned long timeout_jiffies;

/** Timeout for external datagram injection [jiffies].
 */
static unsigned long ext_injection_timeout_jiffies;

#endif

/*****************************************************************************/

void ec_master_clear_slave_configs(ec_master_t *);
void ec_master_clear_domains(ec_master_t *);
static int ec_master_idle_thread(void *);
static int ec_master_operation_thread(void *);
#ifdef EC_EOE
static int ec_master_eoe_thread(void *);
#endif
void ec_master_find_dc_ref_clock(ec_master_t *);

/*****************************************************************************/

/** Static variables initializer.
*/
void ec_master_init_static(void)
{
#ifdef EC_HAVE_CYCLES
    timeout_cycles = (cycles_t) EC_IO_TIMEOUT /* us */ * (cpu_khz / 1000);
    ext_injection_timeout_cycles = (cycles_t) EC_SDO_INJECTION_TIMEOUT /* us */ * (cpu_khz / 1000);
#else
    // one jiffy may always elapse between time measurement
    timeout_jiffies = max(EC_IO_TIMEOUT * HZ / 1000000, 1);
    ext_injection_timeout_jiffies = max(EC_SDO_INJECTION_TIMEOUT * HZ / 1000000, 1);
#endif
}

/*****************************************************************************/

/**
   Master constructor.
   \return 0 in case of success, else < 0
*/

int ec_master_init(ec_master_t *master, /**< EtherCAT master */
        unsigned int index, /**< master index */
        const uint8_t *main_mac, /**< MAC address of main device */
        const uint8_t *backup_mac, /**< MAC address of backup device */
        dev_t device_number, /**< Character device number. */
        struct class *class, /**< Device class. */
        unsigned int debug_level /**< Debug level (module parameter). */
        )
{
    int ret;

    master->index = index;
    master->reserved = 0;

    sema_init(&master->master_sem, 1);

    master->main_mac = main_mac;
    master->backup_mac = backup_mac;

    sema_init(&master->device_sem, 1);

    master->phase = EC_ORPHANED;
    master->active = 0;
    master->config_changed = 0;
    master->injection_seq_fsm = 0;
    master->injection_seq_rt = 0;

    master->slaves = NULL;
    master->slave_count = 0;
    
    INIT_LIST_HEAD(&master->configs);
    INIT_LIST_HEAD(&master->domains);

    master->app_time = 0ULL;
    master->app_start_time = 0ULL;
    master->has_app_time = 0;

    master->scan_busy = 0;
    master->allow_scan = 1;
    sema_init(&master->scan_sem, 1);
    init_waitqueue_head(&master->scan_queue);

    master->config_busy = 0;
    sema_init(&master->config_sem, 1);
    init_waitqueue_head(&master->config_queue);
    
    INIT_LIST_HEAD(&master->datagram_queue);
    master->datagram_index = 0;

    INIT_LIST_HEAD(&master->ext_datagram_queue);
    sema_init(&master->ext_queue_sem, 1);

    INIT_LIST_HEAD(&master->external_datagram_queue);
    
    // send interval in IDLE phase
    ec_master_set_send_interval(master, 1000000 / HZ);

    master->debug_level = debug_level;
    master->stats.timeouts = 0;
    master->stats.corrupted = 0;
    master->stats.unmatched = 0;
    master->stats.output_jiffies = 0;

    master->thread = NULL;

#ifdef EC_EOE
    master->eoe_thread = NULL;
    INIT_LIST_HEAD(&master->eoe_handlers);
#endif

    sema_init(&master->io_sem, 1);
    master->fsm_queue_lock_cb = ec_master_internal_lock_cb;
    master->fsm_queue_unlock_cb = ec_master_internal_unlock_cb;
    master->fsm_queue_locking_data = master;
    master->app_fsm_queue_lock_cb = NULL;
    master->app_fsm_queue_unlock_cb = NULL;
    master->app_fsm_queue_locking_data = NULL;

    INIT_LIST_HEAD(&master->sii_requests);
    init_waitqueue_head(&master->sii_queue);

    INIT_LIST_HEAD(&master->reg_requests);
    init_waitqueue_head(&master->reg_queue);

    // init devices
    ret = ec_device_init(&master->main_device, master);
    if (ret < 0)
        goto out_return;

    ret = ec_device_init(&master->backup_device, master);
    if (ret < 0)
        goto out_clear_main;

    // init state machine datagram
    ec_datagram_init(&master->fsm_datagram);
    snprintf(master->fsm_datagram.name, EC_DATAGRAM_NAME_SIZE, "master-fsm");
    ret = ec_datagram_prealloc(&master->fsm_datagram, EC_MAX_DATA_SIZE);
    if (ret < 0) {
        ec_datagram_clear(&master->fsm_datagram);
        EC_MASTER_ERR(master, "Failed to allocate FSM datagram.\n");
        goto out_clear_backup;
    }

    // create state machine object
    ec_fsm_master_init(&master->fsm, master, &master->fsm_datagram);

    // init reference sync datagram
    ec_datagram_init(&master->ref_sync_datagram);
    snprintf(master->ref_sync_datagram.name, EC_DATAGRAM_NAME_SIZE, "refsync");
    ret = ec_datagram_apwr(&master->ref_sync_datagram, 0, 0x0910, 8);
    if (ret < 0) {
        ec_datagram_clear(&master->ref_sync_datagram);
        EC_MASTER_ERR(master, "Failed to allocate reference"
                " synchronisation datagram.\n");
        goto out_clear_fsm;
    }

    // init sync datagram
    ec_datagram_init(&master->sync_datagram);
    snprintf(master->sync_datagram.name, EC_DATAGRAM_NAME_SIZE, "sync");
    ret = ec_datagram_prealloc(&master->sync_datagram, 4);
    if (ret < 0) {
        ec_datagram_clear(&master->sync_datagram);
        EC_MASTER_ERR(master, "Failed to allocate"
                " synchronisation datagram.\n");
        goto out_clear_ref_sync;
    }

    // init sync monitor datagram
    ec_datagram_init(&master->sync_mon_datagram);
    snprintf(master->sync_mon_datagram.name, EC_DATAGRAM_NAME_SIZE, "syncmon");
    ret = ec_datagram_brd(&master->sync_mon_datagram, 0x092c, 4);
    if (ret < 0) {
        ec_datagram_clear(&master->sync_mon_datagram);
        EC_MASTER_ERR(master, "Failed to allocate sync"
                " monitoring datagram.\n");
        goto out_clear_sync;
    }

    ec_master_find_dc_ref_clock(master);

    // init character device
    ret = ec_cdev_init(&master->cdev, master, device_number);
    if (ret)
        goto out_clear_sync_mon;
    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
    master->class_device = device_create(class, NULL,
            MKDEV(MAJOR(device_number), master->index), NULL,
            "EtherCAT%u", master->index);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26)
    master->class_device = device_create(class, NULL,
            MKDEV(MAJOR(device_number), master->index),
            "EtherCAT%u", master->index);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 15)
    master->class_device = class_device_create(class, NULL,
            MKDEV(MAJOR(device_number), master->index), NULL,
            "EtherCAT%u", master->index);
#else
    master->class_device = class_device_create(class,
            MKDEV(MAJOR(device_number), master->index), NULL,
            "EtherCAT%u", master->index);
#endif
    if (IS_ERR(master->class_device)) {
        EC_MASTER_ERR(master, "Failed to create class device!\n");
        ret = PTR_ERR(master->class_device);
        goto out_clear_cdev;
    }

    return 0;

out_clear_cdev:
    ec_cdev_clear(&master->cdev);
out_clear_sync_mon:
    ec_datagram_clear(&master->sync_mon_datagram);
out_clear_sync:
    ec_datagram_clear(&master->sync_datagram);
out_clear_ref_sync:
    ec_datagram_clear(&master->ref_sync_datagram);
out_clear_fsm:
    ec_fsm_master_clear(&master->fsm);
    ec_datagram_clear(&master->fsm_datagram);
out_clear_backup:
    ec_device_clear(&master->backup_device);
out_clear_main:
    ec_device_clear(&master->main_device);
out_return:
    return ret;
}

/*****************************************************************************/

/** Destructor.
*/
void ec_master_clear(
        ec_master_t *master /**< EtherCAT master */
        )
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26)
    device_unregister(master->class_device);
#else
    class_device_unregister(master->class_device);
#endif

    ec_cdev_clear(&master->cdev);
    
#ifdef EC_EOE
    ec_master_clear_eoe_handlers(master);
#endif
    ec_master_clear_domains(master);
    ec_master_clear_slave_configs(master);
    ec_master_clear_slaves(master);

    ec_datagram_clear(&master->sync_mon_datagram);
    ec_datagram_clear(&master->sync_datagram);
    ec_datagram_clear(&master->ref_sync_datagram);
    ec_fsm_master_clear(&master->fsm);
    ec_datagram_clear(&master->fsm_datagram);
    ec_device_clear(&master->backup_device);
    ec_device_clear(&master->main_device);
}

/*****************************************************************************/

#ifdef EC_EOE
/** Clear and free all EoE handlers.
 */
void ec_master_clear_eoe_handlers(
        ec_master_t *master /**< EtherCAT master */
        )
{
    ec_eoe_t *eoe, *next;

    list_for_each_entry_safe(eoe, next, &master->eoe_handlers, list) {
        list_del(&eoe->list);
        ec_eoe_clear(eoe);
        kfree(eoe);
    }
}
#endif

/*****************************************************************************/

/** Clear all slave configurations.
 */
void ec_master_clear_slave_configs(ec_master_t *master)
{
    ec_slave_config_t *sc, *next;

    list_for_each_entry_safe(sc, next, &master->configs, list) {
        list_del(&sc->list);
        ec_slave_config_clear(sc);
        kfree(sc);
    }
}

/*****************************************************************************/

/** Clear all slaves.
 */
void ec_master_clear_slaves(ec_master_t *master)
{
    ec_slave_t *slave;

    master->dc_ref_clock = NULL;

    // external requests are obsolete, so we wake pending waiters and remove
    // them from the list

    while (!list_empty(&master->sii_requests)) {
        ec_sii_write_request_t *request =
            list_entry(master->sii_requests.next,
                    ec_sii_write_request_t, list);
        list_del_init(&request->list); // dequeue
        EC_MASTER_WARN(master, "Discarding SII request, slave %u about"
                " to be deleted.\n", request->slave->ring_position);
        request->state = EC_INT_REQUEST_FAILURE;
        wake_up(&master->sii_queue);
    }

    while (!list_empty(&master->reg_requests)) {
        ec_reg_request_t *request =
            list_entry(master->reg_requests.next, ec_reg_request_t, list);
        list_del_init(&request->list); // dequeue
        EC_MASTER_WARN(master, "Discarding register request, slave %u"
                " about to be deleted.\n", request->slave->ring_position);
        request->state = EC_INT_REQUEST_FAILURE;
        wake_up(&master->reg_queue);
    }

    master->fsm_queue_lock_cb(master->fsm_queue_locking_data);
    for (slave = master->slaves;
            slave < master->slaves + master->slave_count;
            slave++) {
        ec_slave_clear(slave);
    }
    master->fsm_queue_unlock_cb(master->fsm_queue_locking_data);

    if (master->slaves) {
        kfree(master->slaves);
        master->slaves = NULL;
    }

    master->slave_count = 0;
}

/*****************************************************************************/

/** Clear all domains.
 */
void ec_master_clear_domains(ec_master_t *master)
{
    ec_domain_t *domain, *next;

    master->fsm_queue_lock_cb(master->fsm_queue_locking_data);
    list_for_each_entry_safe(domain, next, &master->domains, list) {
        list_del(&domain->list);
        ec_domain_clear(domain);
        kfree(domain);
    }
    master->fsm_queue_unlock_cb(master->fsm_queue_locking_data);
}

/*****************************************************************************/

/** Clear the configuration applied by the application.
 */
void ec_master_clear_config(
        ec_master_t *master /**< EtherCAT master. */
        )
{
    down(&master->master_sem);
    ec_master_clear_domains(master);
    ec_master_clear_slave_configs(master);
    up(&master->master_sem);
}

/*****************************************************************************/

/** Internal sending callback.
 */
void ec_master_internal_lock_cb(
        void *cb_data /**< Callback data. */
        )
{
    ec_master_t *master = (ec_master_t *) cb_data;
    down(&master->io_sem);
}

/*****************************************************************************/

/** Internal receiving callback.
 */
void ec_master_internal_unlock_cb(
        void *cb_data /**< Callback data. */
        )
{
    ec_master_t *master = (ec_master_t *) cb_data;
    up(&master->io_sem);
}

/*****************************************************************************/

/** Starts the master thread.
 *
 * \retval  0 Success.
 * \retval <0 Error code.
 */
int ec_master_thread_start(
        ec_master_t *master, /**< EtherCAT master */
        int (*thread_func)(void *), /**< thread function to start */
        const char *name /**< Thread name. */
        )
{
    EC_MASTER_INFO(master, "Starting %s thread.\n", name);
    master->thread = kthread_run(thread_func, master, name);
    if (IS_ERR(master->thread)) {
        int err = (int) PTR_ERR(master->thread);
        EC_MASTER_ERR(master, "Failed to start master thread (error %i)!\n",
                err);
        master->thread = NULL;
        return err;
    }
    
    return 0;
}

/*****************************************************************************/

/** Stops the master thread.
 */
void ec_master_thread_stop(
        ec_master_t *master /**< EtherCAT master */
        )
{
    unsigned long sleep_jiffies;
    
    if (!master->thread) {
        EC_MASTER_WARN(master, "%s(): Already finished!\n", __func__);
        return;
    }

    EC_MASTER_DBG(master, 1, "Stopping master thread.\n");

    kthread_stop(master->thread);
    master->thread = NULL;
    EC_MASTER_INFO(master, "Master thread exited.\n");

    if (master->fsm_datagram.state != EC_DATAGRAM_SENT)
        return;
    
    // wait for FSM datagram
    sleep_jiffies = max(HZ / 100, 1); // 10 ms, at least 1 jiffy
    schedule_timeout(sleep_jiffies);
}

/*****************************************************************************/

/** Transition function from ORPHANED to IDLE phase.
 */
int ec_master_enter_idle_phase(
        ec_master_t *master /**< EtherCAT master */
        )
{
    int ret;

    EC_MASTER_DBG(master, 1, "ORPHANED -> IDLE.\n");

    master->fsm_queue_lock_cb = ec_master_internal_lock_cb;
    master->fsm_queue_unlock_cb = ec_master_internal_unlock_cb;
    master->fsm_queue_locking_data = master;

    master->phase = EC_IDLE;

    // reset number of responding slaves to trigger scanning
    master->fsm.slaves_responding = 0;

    ret = ec_master_thread_start(master, ec_master_idle_thread,
            "EtherCAT-IDLE");
    if (ret)
        master->phase = EC_ORPHANED;

    return ret;
}

/*****************************************************************************/

/** Transition function from IDLE to ORPHANED phase.
 */
void ec_master_leave_idle_phase(ec_master_t *master /**< EtherCAT master */)
{
    EC_MASTER_DBG(master, 1, "IDLE -> ORPHANED.\n");

    master->phase = EC_ORPHANED;
    
#ifdef EC_EOE
    ec_master_eoe_stop(master);
#endif
    ec_master_thread_stop(master);

    down(&master->master_sem);
    ec_master_clear_slaves(master);
    up(&master->master_sem);
}

/*****************************************************************************/

/** Transition function from IDLE to OPERATION phase.
 */
int ec_master_enter_operation_phase(ec_master_t *master /**< EtherCAT master */)
{
    int ret = 0;
    ec_slave_t *slave;
#ifdef EC_EOE
    ec_eoe_t *eoe;
#endif

    EC_MASTER_DBG(master, 1, "IDLE -> OPERATION.\n");

    down(&master->config_sem);
    if (master->config_busy) {
        up(&master->config_sem);

        // wait for slave configuration to complete
        ret = wait_event_interruptible(master->config_queue,
                    !master->config_busy);
        if (ret) {
            EC_MASTER_INFO(master, "Finishing slave configuration"
                    " interrupted by signal.\n");
            goto out_allow;
        }

        EC_MASTER_DBG(master, 1, "Waiting for pending slave"
                " configuration returned.\n");
    } else {
        up(&master->config_sem);
    }

    down(&master->scan_sem);
    master->allow_scan = 0; // 'lock' the slave list
    if (!master->scan_busy) {
        up(&master->scan_sem);
    } else {
        up(&master->scan_sem);

        // wait for slave scan to complete
        ret = wait_event_interruptible(master->scan_queue, !master->scan_busy);
        if (ret) {
            EC_MASTER_INFO(master, "Waiting for slave scan"
                    " interrupted by signal.\n");
            goto out_allow;
        }
        
        EC_MASTER_DBG(master, 1, "Waiting for pending"
                " slave scan returned.\n");
    }

    // set states for all slaves
    for (slave = master->slaves;
            slave < master->slaves + master->slave_count;
            slave++) {
        ec_slave_request_state(slave, EC_SLAVE_STATE_PREOP);
    }

#ifdef EC_EOE
    // ... but set EoE slaves to OP
    list_for_each_entry(eoe, &master->eoe_handlers, list) {
        if (ec_eoe_is_open(eoe))
            ec_slave_request_state(eoe->slave, EC_SLAVE_STATE_OP);
    }
#endif

    master->phase = EC_OPERATION;
    master->app_fsm_queue_lock_cb = NULL;
    master->app_fsm_queue_unlock_cb = NULL;
    master->app_fsm_queue_locking_data = NULL;
    return ret;
    
out_allow:
    master->allow_scan = 1;
    return ret;
}

/*****************************************************************************/

/** Transition function from OPERATION to IDLE phase.
 */
void ec_master_leave_operation_phase(
        ec_master_t *master /**< EtherCAT master */
        )
{
    if (master->active) {
        ecrt_master_deactivate(master); // also clears config
    } else {
        ec_master_clear_config(master);
    }

    EC_MASTER_DBG(master, 1, "OPERATION -> IDLE.\n");

    master->phase = EC_IDLE;
}

/*****************************************************************************/

/** Injects external datagrams that fit into the datagram queue.
 */
void ec_master_inject_external_datagrams(
        ec_master_t *master /**< EtherCAT master */
        )
{
    ec_datagram_t *datagram, *n;
    size_t queue_size = 0;

    list_for_each_entry(datagram, &master->datagram_queue, queue) {
        queue_size += datagram->data_size;
    }

    list_for_each_entry_safe(datagram, n, &master->external_datagram_queue,
            queue) {
        queue_size += datagram->data_size;
        if (queue_size <= master->max_queue_size) {
            list_del_init(&datagram->queue);
#if DEBUG_INJECT
            EC_MASTER_DBG(master, 0, "Injecting external datagram %08x"
                    " size=%u, queue_size=%u\n", (unsigned int) datagram,
                    datagram->data_size, queue_size);
#endif
#ifdef EC_HAVE_CYCLES
            datagram->cycles_sent = 0;
#endif
            datagram->jiffies_sent = 0;
            ec_master_queue_datagram(master, datagram);
        }
        else {
            if (datagram->data_size > master->max_queue_size) {
                list_del_init(&datagram->queue);
                datagram->state = EC_DATAGRAM_ERROR;
                EC_MASTER_ERR(master, "External datagram %p is too large,"
                        " size=%zu, max_queue_size=%zu\n",
                        datagram, datagram->data_size,
                        master->max_queue_size);
            } else {
#ifdef EC_HAVE_CYCLES
                cycles_t cycles_now = get_cycles();

                if (cycles_now - datagram->cycles_sent
                        > ext_injection_timeout_cycles)
#else
                if (jiffies - datagram->jiffies_sent
                        > ext_injection_timeout_jiffies)
#endif
                {
                    unsigned int time_us;

                    list_del_init(&datagram->queue);
                    datagram->state = EC_DATAGRAM_ERROR;
#ifdef EC_HAVE_CYCLES
                    time_us = (unsigned int)
                        ((cycles_now - datagram->cycles_sent) * 1000LL)
                        / cpu_khz;
#else
                    time_us = (unsigned int)
                        ((jiffies - datagram->jiffies_sent) * 1000000 / HZ);
#endif
                    EC_MASTER_ERR(master, "Timeout %u us: Injecting"
                            " external datagram %p size=%zu,"
                            " max_queue_size=%zu\n", time_us, datagram,
                            datagram->data_size, master->max_queue_size);
                }
#if DEBUG_INJECT
                else {
                    EC_MASTER_DBG(master, 0, "Deferred injecting"
                            " of external datagram %p"
                            " size=%u, queue_size=%u\n",
                            datagram, datagram->data_size, queue_size);
                }
#endif
            }
        }
    }
}

/*****************************************************************************/

/** Sets the expected interval between calls to ecrt_master_send
 * and calculates the maximum amount of data to queue.
 */
void ec_master_set_send_interval(
        ec_master_t *master, /**< EtherCAT master */
        unsigned int send_interval /**< Send interval */
        )
{
    master->send_interval = send_interval;
    master->max_queue_size =
        (send_interval * 1000) / EC_BYTE_TRANSMISSION_TIME_NS;
    master->max_queue_size -= master->max_queue_size / 10;
}

/*****************************************************************************/

/** Places an external datagram in the sdo datagram queue.
 */
void ec_master_queue_external_datagram(
        ec_master_t *master, /**< EtherCAT master */
        ec_datagram_t *datagram /**< datagram */
        )
{
    ec_datagram_t *queued_datagram;

    master->fsm_queue_lock_cb(master->fsm_queue_locking_data);

    // check, if the datagram is already queued
    list_for_each_entry(queued_datagram, &master->external_datagram_queue,
            queue) {
        if (queued_datagram == datagram) {
            datagram->state = EC_DATAGRAM_QUEUED;
            return;
        }
    }

#if DEBUG_INJECT
    EC_MASTER_DBG(master, 0, "Requesting external datagram %p size=%u\n",
            datagram, datagram->data_size);
#endif

    list_add_tail(&datagram->queue, &master->external_datagram_queue);
    datagram->state = EC_DATAGRAM_QUEUED;
#ifdef EC_HAVE_CYCLES
    datagram->cycles_sent = get_cycles();
#endif
    datagram->jiffies_sent = jiffies;

    master->fsm.idle = 0;
    master->fsm_queue_unlock_cb(master->fsm_queue_locking_data);
}

/*****************************************************************************/

/** Places a datagram in the datagram queue.
 */
void ec_master_queue_datagram(
        ec_master_t *master, /**< EtherCAT master */
        ec_datagram_t *datagram /**< datagram */
        )
{
    ec_datagram_t *queued_datagram;

    switch (datagram->state) {
        case EC_DATAGRAM_QUEUED:
            datagram->skip_count++;
            EC_MASTER_DBG(master, 1, "Skipping already queued datagram %p.\n",
                    datagram);
            break;

        case EC_DATAGRAM_SENT:
            datagram->skip_count++;
            EC_MASTER_DBG(master, 1, "Skipping already sent datagram %p.\n",
                    datagram);
            break;

        default:
            break;
    }

#ifdef EC_HAVE_CYCLES
    datagram->cycles_sent = get_cycles();
#endif
    datagram->jiffies_sent = jiffies;

    /* It is possible, that a datagram in the queue is re-initialized with the
     * ec_datagram_<type>() methods and then shall be queued with this method.
     * In that case, the state is already reset to EC_DATAGRAM_INIT. Check if
     * the datagram is queued to avoid duplicate queuing (which results in an
     * infinite loop!). Set the state to EC_DATAGRAM_QUEUED again, probably
     * causing an unmatched datagram. */
    list_for_each_entry(queued_datagram, &master->datagram_queue, queue) {
        if (queued_datagram == datagram) {
            datagram->skip_count++;
            EC_MASTER_DBG(master, 1, "Skipping re-initialized datagram %p.\n",
                    datagram);
            datagram->state = EC_DATAGRAM_QUEUED;
            return;
        }
    }

    list_add_tail(&datagram->queue, &master->datagram_queue);
    datagram->state = EC_DATAGRAM_QUEUED;
}

/*****************************************************************************/

/** Places a datagram in the non-application datagram queue.
 */
void ec_master_queue_datagram_ext(
        ec_master_t *master, /**< EtherCAT master */
        ec_datagram_t *datagram /**< datagram */
        )
{
    down(&master->ext_queue_sem);
    list_add_tail(&datagram->queue, &master->ext_datagram_queue);
    up(&master->ext_queue_sem);
}

/*****************************************************************************/

/* Utility functions */

static int is_zero(const uint8_t *p, size_t n)
{
    while (n--)
        if (*p++)
            return 0;
    return 1;
}

static int index_in_use(ec_master_t *master, uint8_t index)
{
    ec_datagram_t *datagram;
    list_for_each_entry(datagram, &master->datagram_queue, queue)
        if (datagram->state == EC_DATAGRAM_SENT && datagram->index == index)
            return 1;
    return 0;
}

static int ec_slave_datagram_to_buffer(
        ec_slave_t *slave,
        uint8_t protocol,
        ec_datagram_t *datagram)
{
    int n = slave->tx_mailbox_buffers_used[protocol];
    if (n >= EC_MBOX_BUFFERS)
        return 0;
    n = (slave->tx_mailbox_buffer_head[protocol] + n) % EC_MBOX_BUFFERS;
    slave->tx_mailbox_buffer_working_counter[protocol][n] =
      datagram->working_counter;
    memcpy(slave->tx_mailbox_buffer + slave->configured_tx_mailbox_size
             * (protocol * EC_MBOX_BUFFERS + n),
           datagram->data,
           slave->configured_tx_mailbox_size);
    slave->tx_mailbox_buffers_used[protocol]++;
    return 1;
}

static int ec_slave_datagram_from_buffer(
        ec_slave_t *slave,
        uint8_t protocol,
        ec_datagram_t *datagram)
{
    int n = slave->tx_mailbox_buffer_head[protocol];
    if (slave->tx_mailbox_buffers_used[protocol] == 0)
        return 0;
    datagram->working_counter =
      slave->tx_mailbox_buffer_working_counter[protocol][n];
    memcpy(datagram->data,
           slave->tx_mailbox_buffer + slave->configured_tx_mailbox_size
             * (protocol * EC_MBOX_BUFFERS + n),
           slave->configured_tx_mailbox_size);
    slave->tx_mailbox_buffer_head[protocol] = (n + 1) % EC_MBOX_BUFFERS;
    slave->tx_mailbox_buffers_used[protocol]--;
    return 1;
}

/*****************************************************************************/

/** Sends the datagrams in the queue.
 *
 * Returns the number of bytes sent.
 */
size_t ec_master_send_datagrams(ec_master_t *master /**< EtherCAT master */)
{
    ec_datagram_t *datagram, *next;
    size_t datagram_size;
    uint8_t *frame_data, *cur_data;
    void *follows_word;
#ifdef EC_HAVE_CYCLES
    cycles_t cycles_start, cycles_sent, cycles_end;
#endif
    unsigned long jiffies_sent;
    unsigned int frame_count, more_datagrams_waiting;
    struct list_head sent_datagrams;
    size_t sent_bytes = 0;

#ifdef EC_HAVE_CYCLES
    cycles_start = get_cycles();
#endif
    frame_count = 0;
    INIT_LIST_HEAD(&sent_datagrams);

    EC_MASTER_DBG(master, 2, "ec_master_send_datagrams\n");

    do {
        int fetch_sent = 0;

        // fetch pointer to transmit socket buffer
        frame_data = ec_device_tx_data(&master->main_device);
        cur_data = frame_data + EC_FRAME_HEADER_SIZE;
        follows_word = NULL;
        more_datagrams_waiting = 0;

        // fill current frame with datagrams
        list_for_each_entry_safe(datagram, next, &master->datagram_queue, queue) {
            ec_slave_t *mbox_slave;
            uint8_t mbox_prot;
            uint8_t last_index;

            if (datagram->state != EC_DATAGRAM_QUEUED) continue;

            // Checking the mailbox after fetching it in the same frame
            // can still return "filled" (possibly device-dependent),
            // so make a new frame for the next check.
            if (fetch_sent &&
                ec_slave_is_mbox_datagram(datagram, EC_DATAGRAM_MAILBOX_CHECK,
                                          &mbox_slave, &mbox_prot)) {
                more_datagrams_waiting = 1;
                break;
            }

            // Do not fetch twice simultaneously from the same mailbox.
            // Answer from the internal buffer instead of fetching when
            // necessary.
            if (ec_slave_is_mbox_datagram(datagram, EC_DATAGRAM_MAILBOX_FETCH,
                                          &mbox_slave, &mbox_prot)) {

                int can_fetch = mbox_slave->tx_mailbox_filled
                                && !mbox_slave->tx_mailbox_fetching;

                if (likely(mbox_slave->tx_mailbox_buffer)
                    && likely(mbox_prot < EC_MBOX_MAX_PROTOCOL)
                    && mbox_prot != EC_MBOX_NO_PROTOCOL
                    && (!can_fetch
                        // try to stop buffers from growing too much
                        || mbox_slave->tx_mailbox_buffers_used[mbox_prot]
                             > EC_MBOX_BUFFERS / 2)
                    && ec_slave_datagram_from_buffer(mbox_slave, mbox_prot, datagram)) {
                    datagram->state = EC_DATAGRAM_RECEIVED;
#ifdef EC_HAVE_CYCLES
                    datagram->cycles_sent = datagram->cycles_received = get_cycles();
#endif
                    datagram->jiffies_sent = datagram->jiffies_received = jiffies;
                    list_del_init(&datagram->queue);
                    if (unlikely(master->debug_level > 1))
                        EC_SLAVE_INFO(mbox_slave,"%p fetching mailbox response"
                          " for protocol %i from buffer\n", datagram, mbox_prot);
                    continue;  // don't need to send this datagram
                }

                if (!can_fetch) {
                    if (mbox_prot == EC_MBOX_NO_PROTOCOL) {
                        datagram->state = EC_DATAGRAM_INIT;
                        list_del_init(&datagram->queue);
                    }
                    continue;  // nothing to fetch, wait
                }

                mbox_slave->tx_mailbox_fetching = 1;
                fetch_sent = 1;
            }

            // does the current datagram fit in the frame?
            datagram_size = EC_DATAGRAM_HEADER_SIZE + datagram->data_size
                + EC_DATAGRAM_FOOTER_SIZE;
            if (cur_data - frame_data + datagram_size > ETH_DATA_LEN) {
                more_datagrams_waiting = 1;
                break;
            }

            // do not reuse the index of a pending datagram to avoid confusion
            // in ec_master_receive_datagrams()
            last_index = master->datagram_index;
            while (index_in_use(master, master->datagram_index))
                if (++master->datagram_index == last_index) {
                    EC_MASTER_ERR(master, "No free datagram index, sending delayed\n");
                    goto break_send;
                }
            datagram->index = master->datagram_index++;

            list_add_tail(&datagram->sent, &sent_datagrams);

            EC_MASTER_DBG(master, 2, "adding datagram 0x%02X\n",
                    datagram->index);

            // set "datagram following" flag in previous frame
            if (follows_word)
                EC_WRITE_U16(follows_word, EC_READ_U16(follows_word) | 0x8000);

            // EtherCAT datagram header
            EC_WRITE_U8 (cur_data,     datagram->type);
            EC_WRITE_U8 (cur_data + 1, datagram->index);
            memcpy(cur_data + 2, datagram->address, EC_ADDR_LEN);
            EC_WRITE_U16(cur_data + 6, datagram->data_size & 0x7FF);
            EC_WRITE_U16(cur_data + 8, 0x0000);
            follows_word = cur_data + 6;
            cur_data += EC_DATAGRAM_HEADER_SIZE;

            // EtherCAT datagram data
            memcpy(cur_data, datagram->data, datagram->data_size);
            cur_data += datagram->data_size;

            // EtherCAT datagram footer
            EC_WRITE_U16(cur_data, 0x0000); // reset working counter
            cur_data += EC_DATAGRAM_FOOTER_SIZE;
        }
break_send:

        if (list_empty(&sent_datagrams)) {
            EC_MASTER_DBG(master, 2, "nothing to send.\n");
            break;
        }

        // EtherCAT frame header
        EC_WRITE_U16(frame_data, ((cur_data - frame_data
                                   - EC_FRAME_HEADER_SIZE) & 0x7FF) | 0x1000);

        // pad frame
        while (cur_data - frame_data < ETH_ZLEN - ETH_HLEN)
            EC_WRITE_U8(cur_data++, 0x00);

        EC_MASTER_DBG(master, 2, "frame size: %zu\n", cur_data - frame_data);

        // send frame
        ec_device_send(&master->main_device, cur_data - frame_data);
        sent_bytes += ETH_HLEN + cur_data - frame_data + ETH_FCS_LEN
          + 20  /* preamble and interframe gap */;
#ifdef EC_HAVE_CYCLES
        cycles_sent = get_cycles();
#endif
        jiffies_sent = jiffies;

        // set datagram states and sending timestamps
        list_for_each_entry_safe(datagram, next, &sent_datagrams, sent) {
            datagram->state = EC_DATAGRAM_SENT;
#ifdef EC_HAVE_CYCLES
            datagram->cycles_sent = cycles_sent;
#endif
            datagram->jiffies_sent = jiffies_sent;
            list_del_init(&datagram->sent); // empty list of sent datagrams
        }

        frame_count++;
    }
    while (more_datagrams_waiting && frame_count < EC_TX_RING_SIZE);

#ifdef EC_HAVE_CYCLES
    if (unlikely(master->debug_level > 1)) {
        cycles_end = get_cycles();
        EC_MASTER_DBG(master, 0, "ec_master_send_datagrams"
                " sent %u frames in %uus.\n", frame_count,
               (unsigned int) (cycles_end - cycles_start) * 1000 / cpu_khz);
    }
#endif
    return sent_bytes;
}

/*****************************************************************************/

/** Processes a received frame.
 *
 * This function is called by the network driver for every received frame.
 * 
 * \return 0 in case of success, else < 0
 */
void ec_master_receive_datagrams(ec_master_t *master, /**< EtherCAT master */
                                 const uint8_t *frame_data, /**< frame data */
                                 size_t size /**< size of the received data */
                                 )
{
    size_t frame_size, data_size;
    uint8_t datagram_type, datagram_index;
    unsigned int cmd_follows, matched;
    const uint8_t *cur_data;
    ec_datagram_t *datagram;

    if (unlikely(size < EC_FRAME_HEADER_SIZE)) {
        if (master->debug_level) {
            EC_MASTER_DBG(master, 0, "Corrupted frame received"
                    " (size %zu < %u byte):\n",
                    size, EC_FRAME_HEADER_SIZE);
            ec_print_data(frame_data, size);
        }
        master->stats.corrupted++;
        ec_master_output_stats(master);
        return;
    }

    cur_data = frame_data;

    // check length of entire frame
    frame_size = EC_READ_U16(cur_data) & 0x07FF;
    cur_data += EC_FRAME_HEADER_SIZE;

    if (unlikely(frame_size > size)) {
        if (master->debug_level) {
            EC_MASTER_DBG(master, 0, "Corrupted frame received"
                    " (invalid frame size %zu for "
                    "received size %zu):\n", frame_size, size);
            ec_print_data(frame_data, size);
        }
        master->stats.corrupted++;
        ec_master_output_stats(master);
        return;
    }

    cmd_follows = 1;
    while (cmd_follows) {
        ec_slave_t *mbox_slave;
        uint8_t mbox_prot;

        // process datagram header
        datagram_type  = EC_READ_U8 (cur_data);
        datagram_index = EC_READ_U8 (cur_data + 1);
        data_size      = EC_READ_U16(cur_data + 6) & 0x07FF;
        cmd_follows    = EC_READ_U16(cur_data + 6) & 0x8000;
        cur_data += EC_DATAGRAM_HEADER_SIZE;

        if (unlikely(cur_data - frame_data
                     + data_size + EC_DATAGRAM_FOOTER_SIZE > size)) {
            if (master->debug_level) {
                EC_MASTER_DBG(master, 0, "Corrupted frame received"
                        " (invalid data size %zu):\n", data_size);
                ec_print_data(frame_data, size);
            }
            master->stats.corrupted++;
            ec_master_output_stats(master);
            return;
        }

        // search for matching datagram in the queue
        matched = 0;
        list_for_each_entry(datagram, &master->datagram_queue, queue) {
            if (datagram->index == datagram_index
                && datagram->state == EC_DATAGRAM_SENT
                && datagram->type == datagram_type
                && datagram->data_size == data_size) {
                matched = 1;
                break;
            }
        }

        // no matching datagram was found
        if (!matched) {
            master->stats.unmatched++;
            ec_master_output_stats(master);

            if (unlikely(master->debug_level > 0)) {
                EC_MASTER_DBG(master, 0, "UNMATCHED datagram:\n");
                ec_print_data(cur_data - EC_DATAGRAM_HEADER_SIZE,
                        EC_DATAGRAM_HEADER_SIZE + data_size
                        + EC_DATAGRAM_FOOTER_SIZE);
#ifdef EC_DEBUG_RING
                ec_device_debug_ring_print(&master->main_device);
#endif
            }

            cur_data += data_size + EC_DATAGRAM_FOOTER_SIZE;
            continue;
        }

        if (datagram->type != EC_DATAGRAM_APWR &&
                datagram->type != EC_DATAGRAM_FPWR &&
                datagram->type != EC_DATAGRAM_BWR &&
                datagram->type != EC_DATAGRAM_LWR) {
            // copy received data into the datagram memory,
            // if something has been read
            memcpy(datagram->data, cur_data, data_size);
        }
        cur_data += data_size;

        // set the datagram's working counter
        datagram->working_counter = EC_READ_U16(cur_data);
        cur_data += EC_DATAGRAM_FOOTER_SIZE;

        // dequeue the received datagram
        datagram->state = EC_DATAGRAM_RECEIVED;
#ifdef EC_HAVE_CYCLES
        datagram->cycles_received = master->main_device.cycles_poll;
#endif
        datagram->jiffies_received = master->main_device.jiffies_poll;
        list_del_init(&datagram->queue);

        if (ec_slave_is_mbox_datagram(datagram, EC_DATAGRAM_MAILBOX_CHECK,
                                      &mbox_slave, &mbox_prot)) {
            mbox_slave->tx_mailbox_filled = ec_slave_mbox_check(datagram);

            if (likely(mbox_slave->tx_mailbox_buffer)
                && likely(mbox_prot < EC_MBOX_MAX_PROTOCOL)) {

                if (mbox_slave->tx_mailbox_filled
                    && mbox_slave->tx_mailbox_buffers_used[mbox_prot] == 0) {
                    // There is something in the mailbox, but not necessarily
                    // for this protocol, and we have nothing buffered for it.
                    // So we reply "no" and fetch the mailbox internally.
                    if (mbox_slave->tx_fetch.state != EC_DATAGRAM_QUEUED
                        && mbox_slave->tx_fetch.state != EC_DATAGRAM_SENT
                        && !ec_slave_mbox_prepare_fetch(mbox_slave,
                              &mbox_slave->tx_fetch, EC_MBOX_NO_PROTOCOL)) {
                        ec_master_queue_datagram(master, &mbox_slave->tx_fetch);
                    }
                    ec_slave_mbox_override_check(datagram, 0);
                    if (unlikely(master->debug_level > 1))
                        EC_SLAVE_INFO(mbox_slave, "%p overriding mailbox"
                          " check = 0 for protocol %i\n", datagram, mbox_prot);
                }

                if (mbox_slave->tx_mailbox_buffers_used[mbox_prot] != 0
                    && !mbox_slave->tx_mailbox_filled) {
                    // There is nothing in the mailbox, but we have something
                    // buffered for this protocol. So we reply "yes" and
                    // answer the following fetch datagram from the buffer.
                    ec_slave_mbox_override_check(datagram, 1);
                    if (unlikely(master->debug_level > 1))
                        EC_SLAVE_INFO(mbox_slave, "%p overriding mailbox"
                          " check = 1 for protocol %i\n", datagram, mbox_prot);
                }
            }
        }

        if (ec_slave_is_mbox_datagram(datagram, EC_DATAGRAM_MAILBOX_FETCH,
                                      &mbox_slave, &mbox_prot)) {
            mbox_slave->tx_mailbox_filled = mbox_slave->tx_mailbox_fetching = 0;
            if (likely(mbox_slave->tx_mailbox_buffer)
                && likely(mbox_prot < EC_MBOX_MAX_PROTOCOL)) {
                uint8_t actual_mbox_prot;
                size_t data_size;

                // quick check for empty datagrams to avoid spurious error messages
                if (datagram->working_counter == 0
                    || (EC_READ_U8(datagram->data + 5) == 0
                        && EC_READ_U16(datagram->data + 8) == 0
                        && is_zero(datagram->data + EC_MBOX_HEADER_SIZE,
                             EC_READ_U16(datagram->data)))) {
                    EC_SLAVE_WARN(mbox_slave, "mailbox empty unexpectedly"
                          " (protocol %i)\n", mbox_prot);
                    actual_mbox_prot = EC_MBOX_NO_PROTOCOL;
                } else if (IS_ERR(ec_slave_mbox_fetch(mbox_slave, datagram,
                                    &actual_mbox_prot, &data_size))
                           || data_size > mbox_slave->configured_tx_mailbox_size) {
                    EC_SLAVE_WARN(mbox_slave, "invalid mailbox response\n");
                    actual_mbox_prot = EC_MBOX_NO_PROTOCOL;
                }

                // If the response is for a different protocol, exchange the
                // datagram with a buffered one if possible. Also do so if it
                // is the wanted protocol, but there is something buffered for
                // it so datagrams are returned in the correct order.
                if (actual_mbox_prot != mbox_prot
                    || mbox_slave->tx_mailbox_buffers_used[mbox_prot] != 0) {

                    if (actual_mbox_prot != EC_MBOX_NO_PROTOCOL) {
                        if (ec_slave_datagram_to_buffer(mbox_slave,
                              actual_mbox_prot, datagram)) {
                            if (unlikely(master->debug_level > 1))
                                EC_SLAVE_INFO(mbox_slave, "%p buffering"
                                  " mailbox response for protocol %i\n",
                                  datagram, actual_mbox_prot);
                        } else {
                            EC_SLAVE_WARN(mbox_slave, "mailbox protocol %i "
                              "buffer overflow, discarding response\n",
                              actual_mbox_prot);
                        }
                    }

                    if (mbox_prot != EC_MBOX_NO_PROTOCOL) {
                        if (ec_slave_datagram_from_buffer(mbox_slave,
                              mbox_prot, datagram)) {
                            if (unlikely(master->debug_level > 1))
                                EC_SLAVE_INFO(mbox_slave, "%p reading mailbox"
                                  " response for protocol %i from buffer\n",
                                  datagram, mbox_prot);
                        } else {
                            EC_SLAVE_WARN(mbox_slave,
                              "mailbox protocol %i response lost\n", mbox_prot);
                            // so ec_slave_mbox_fetch will report an error
                            ec_datagram_zero(datagram);
                        }
                    }
                }
            }
        }

        // When several sources try to send to the mailbox simultaneously,
        // only one will succeed. The other datagrams are not processed by
        // the slave which can be seen by a working_counter which is still 0.
        // Instead of making all users retry the sending, we do it here
        // centrally. We limit the number of retries to avoid infinite
        // retries in case of invalid send datagrams.
        if (ec_slave_is_mbox_datagram(datagram, EC_DATAGRAM_MAILBOX_SEND,
                                      &mbox_slave, &mbox_prot)
            && datagram->working_counter == 0
            && datagram->mailbox_send_retries > 0) {
            datagram->mailbox_send_retries--;
            if (unlikely(master->debug_level > 1))
                EC_SLAVE_INFO(mbox_slave, "retrying mailbox send"
                    " datagram %p\n", datagram);
            ec_master_queue_datagram(master, datagram);
        }
    }
}

/*****************************************************************************/

/** Output master statistics.
 *
 * This function outputs statistical data on demand, but not more often than
 * necessary. The output happens at most once a second.
 */
void ec_master_output_stats(ec_master_t *master /**< EtherCAT master */)
{
    if (unlikely(jiffies - master->stats.output_jiffies >= HZ)) {
        master->stats.output_jiffies = jiffies;

        if (master->stats.timeouts) {
            EC_MASTER_WARN(master, "%u datagram%s TIMED OUT!\n",
                    master->stats.timeouts,
                    master->stats.timeouts == 1 ? "" : "s");
            master->stats.timeouts = 0;
        }
        if (master->stats.corrupted) {
            EC_MASTER_WARN(master, "%u frame%s CORRUPTED!\n",
                    master->stats.corrupted,
                    master->stats.corrupted == 1 ? "" : "s");
            master->stats.corrupted = 0;
        }
        if (master->stats.unmatched) {
            EC_MASTER_WARN(master, "%u datagram%s UNMATCHED!\n",
                    master->stats.unmatched,
                    master->stats.unmatched == 1 ? "" : "s");
            master->stats.unmatched = 0;
        }
    }
}


/*****************************************************************************/

#ifdef EC_USE_HRTIMER

/*
 * Sleep related functions:
 */
static enum hrtimer_restart ec_master_nanosleep_wakeup(struct hrtimer *timer)
{
    struct hrtimer_sleeper *t =
        container_of(timer, struct hrtimer_sleeper, timer);
    struct task_struct *task = t->task;

    t->task = NULL;
    if (task)
        wake_up_process(task);

    return HRTIMER_NORESTART;
}

/*****************************************************************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)

/* compatibility with new hrtimer interface */
static inline ktime_t hrtimer_get_expires(const struct hrtimer *timer)
{
    return timer->expires;
}

/*****************************************************************************/

static inline void hrtimer_set_expires(struct hrtimer *timer, ktime_t time)
{
    timer->expires = time;
}

#endif

/*****************************************************************************/

void ec_master_nanosleep(const unsigned long nsecs)
{
    struct hrtimer_sleeper t;
    enum hrtimer_mode mode = HRTIMER_MODE_REL;

    hrtimer_init(&t.timer, CLOCK_MONOTONIC, mode);
    t.timer.function = ec_master_nanosleep_wakeup;
    t.task = current;
#ifdef CONFIG_HIGH_RES_TIMERS
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 24)
    t.timer.cb_mode = HRTIMER_CB_IRQSAFE_NO_RESTART;
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 26)
    t.timer.cb_mode = HRTIMER_CB_IRQSAFE_NO_SOFTIRQ;
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 28)
    t.timer.cb_mode = HRTIMER_CB_IRQSAFE_UNLOCKED;
#endif
#endif
    hrtimer_set_expires(&t.timer, ktime_set(0, nsecs));

    do {
        set_current_state(TASK_INTERRUPTIBLE);
        hrtimer_start(&t.timer, hrtimer_get_expires(&t.timer), mode);

        if (likely(t.task))
            schedule();

        hrtimer_cancel(&t.timer);
        mode = HRTIMER_MODE_ABS;

    } while (t.task && !signal_pending(current));
}

#endif // EC_USE_HRTIMER

/*****************************************************************************/

/** Master kernel thread function for IDLE phase.
 */
static int ec_master_idle_thread(void *priv_data)
{
    ec_master_t *master = (ec_master_t *) priv_data;
    ec_slave_t *slave = NULL;
    int fsm_exec;
    size_t sent_bytes;

    // send interval in IDLE phase
    ec_master_set_send_interval(master, 1000000 / HZ); 

    EC_MASTER_DBG(master, 1, "Idle thread running with send interval = %u us,"
            " max data size=%zu\n", master->send_interval,
            master->max_queue_size);

    while (!kthread_should_stop()) {
        ec_datagram_output_stats(&master->fsm_datagram);

        // receive
        master->fsm_queue_lock_cb(master->fsm_queue_locking_data);
        ecrt_master_receive(master);
        master->fsm_queue_unlock_cb(master->fsm_queue_locking_data);

        fsm_exec = 0;
        // execute master & slave state machines
        if (down_interruptible(&master->master_sem))
            break;
        fsm_exec = ec_fsm_master_exec(&master->fsm);
        for (slave = master->slaves;
                slave < master->slaves + master->slave_count;
                slave++) {
            ec_fsm_slave_exec(&slave->fsm);
        }
        up(&master->master_sem);

        // queue and send
        master->fsm_queue_lock_cb(master->fsm_queue_locking_data);
        if (fsm_exec) {
            ec_master_queue_datagram(master, &master->fsm_datagram);
        }
        sent_bytes = ecrt_master_send(master);
        master->fsm_queue_unlock_cb(master->fsm_queue_locking_data);

        if (ec_fsm_master_idle(&master->fsm)) {
#ifdef EC_USE_HRTIMER
            ec_master_nanosleep(master->send_interval * 1000);
#else
            set_current_state(TASK_INTERRUPTIBLE);
            schedule_timeout(1);
#endif
        } else {
#ifdef EC_USE_HRTIMER
            ec_master_nanosleep(sent_bytes * EC_BYTE_TRANSMISSION_TIME_NS * 6 / 5);
#else
            schedule();
#endif
        }
    }
    
    EC_MASTER_DBG(master, 1, "Master IDLE thread exiting...\n");

    return 0;
}

/*****************************************************************************/

/** Master kernel thread function for OPERATION phase.
 */
static int ec_master_operation_thread(void *priv_data)
{
    ec_master_t *master = (ec_master_t *) priv_data;
    ec_slave_t *slave = NULL;
    int fsm_exec;

    EC_MASTER_DBG(master, 1, "Operation thread running"
            " with fsm interval = %u us, max data size=%zu\n",
            master->send_interval, master->max_queue_size);

    while (!kthread_should_stop()) {
        ec_datagram_output_stats(&master->fsm_datagram);

        if (master->injection_seq_rt == master->injection_seq_fsm) {
            // output statistics
            ec_master_output_stats(master);

            fsm_exec = 0;
            // execute master & slave state machines
            if (down_interruptible(&master->master_sem))
                break;
            fsm_exec += ec_fsm_master_exec(&master->fsm);
            for (slave = master->slaves;
                    slave < master->slaves + master->slave_count;
                    slave++) {
                ec_fsm_slave_exec(&slave->fsm);
            }
            up(&master->master_sem);

            // inject datagrams (let the rt thread queue them, see
            // ecrt_master_send)
            if (fsm_exec)
                master->injection_seq_fsm++;
        }

#ifdef EC_USE_HRTIMER
        // the op thread should not work faster than the sending RT thread
        ec_master_nanosleep(master->send_interval * 1000);
#else
        if (ec_fsm_master_idle(&master->fsm)) {
            set_current_state(TASK_INTERRUPTIBLE);
            schedule_timeout(1);
        }
        else {
            schedule();
        }
#endif
    }
    
    EC_MASTER_DBG(master, 1, "Master OP thread exiting...\n");
    return 0;
}

/*****************************************************************************/

#ifdef EC_EOE
/** Starts Ethernet over EtherCAT processing on demand.
 */
void ec_master_eoe_start(ec_master_t *master /**< EtherCAT master */)
{
    struct sched_param param = { .sched_priority = 0 };

    if (master->eoe_thread) {
        EC_MASTER_WARN(master, "EoE already running!\n");
        return;
    }

    if (list_empty(&master->eoe_handlers))
        return;

    EC_MASTER_INFO(master, "Starting EoE thread.\n");
    master->eoe_thread = kthread_run(ec_master_eoe_thread, master,
            "EtherCAT-EoE");
    if (IS_ERR(master->eoe_thread)) {
        int err = (int) PTR_ERR(master->eoe_thread);
        EC_MASTER_ERR(master, "Failed to start EoE thread (error %i)!\n",
                err);
        master->eoe_thread = NULL;
        return;
    }

    sched_setscheduler(master->eoe_thread, SCHED_NORMAL, &param);
    set_user_nice(master->eoe_thread, 0);
}

/*****************************************************************************/

/** Stops the Ethernet over EtherCAT processing.
 */
void ec_master_eoe_stop(ec_master_t *master /**< EtherCAT master */)
{
    if (master->eoe_thread) {
        EC_MASTER_INFO(master, "Stopping EoE thread.\n");

        kthread_stop(master->eoe_thread);
        master->eoe_thread = NULL;
        EC_MASTER_INFO(master, "EoE thread exited.\n");
    }
}

/*****************************************************************************/

/** Does the Ethernet over EtherCAT processing.
 */
static int ec_master_eoe_thread(void *priv_data)
{
    ec_master_t *master = (ec_master_t *) priv_data;
    ec_eoe_t *eoe;
    unsigned int none_open, sth_to_send, all_idle;

    EC_MASTER_DBG(master, 1, "EoE thread running.\n");

    while (!kthread_should_stop()) {
        none_open = 1;
        all_idle = 1;

        list_for_each_entry(eoe, &master->eoe_handlers, list) {
            if (ec_eoe_is_open(eoe)) {
                none_open = 0;
                break;
            }
        }
        if (none_open)
            goto schedule;

        // receive datagrams
        master->fsm_queue_lock_cb(master->fsm_queue_locking_data);
        ecrt_master_receive(master);
        master->fsm_queue_unlock_cb(master->fsm_queue_locking_data);

        // actual EoE processing
        sth_to_send = 0;
        list_for_each_entry(eoe, &master->eoe_handlers, list) {
            ec_eoe_run(eoe);
            if (eoe->queue_datagram
                || eoe->datagram.state == EC_DATAGRAM_PREQUEUED) {
                sth_to_send = 1;
            }
            if (!ec_eoe_is_idle(eoe)) {
                all_idle = 0;
            }
        }

        if (sth_to_send) {
            list_for_each_entry(eoe, &master->eoe_handlers, list) {
                ec_eoe_queue(eoe);
            }
            // (try to) send datagrams
            master->fsm_queue_lock_cb(master->fsm_queue_locking_data);
            ecrt_master_send_ext(master);
            master->fsm_queue_unlock_cb(master->fsm_queue_locking_data);
        }

schedule:
        if (all_idle) {
            set_current_state(TASK_INTERRUPTIBLE);
            schedule_timeout(1);
        } else {
            schedule();
        }
    }
    
    EC_MASTER_DBG(master, 1, "EoE thread exiting...\n");
    return 0;
}
#endif

/*****************************************************************************/

/** Detaches the slave configurations from the slaves.
 */
void ec_master_detach_slave_configs(
        ec_master_t *master /**< EtherCAT master. */
        )
{
    ec_slave_config_t *sc;

    list_for_each_entry(sc, &master->configs, list) {
        ec_slave_config_detach(sc); 
    }
}

/*****************************************************************************/

/** Attaches the slave configurations to the slaves.
 */
void ec_master_attach_slave_configs(
        ec_master_t *master /**< EtherCAT master. */
        )
{
    ec_slave_config_t *sc;

    list_for_each_entry(sc, &master->configs, list) {
        ec_slave_config_attach(sc);
    }
}

/*****************************************************************************/

/** Common implementation for ec_master_find_slave()
 * and ec_master_find_slave_const().
 */
#define EC_FIND_SLAVE \
    do { \
        if (alias) { \
            for (; slave < master->slaves + master->slave_count; \
                    slave++) { \
                if (slave->effective_alias == alias) \
                break; \
            } \
            if (slave == master->slaves + master->slave_count) \
            return NULL; \
        } \
        \
        slave += position; \
        if (slave < master->slaves + master->slave_count) { \
            return slave; \
        } else { \
            return NULL; \
        } \
    } while (0)

/** Finds a slave in the bus, given the alias and position.
 */
ec_slave_t *ec_master_find_slave(
        ec_master_t *master, /**< EtherCAT master. */
        uint16_t alias, /**< Slave alias. */
        uint16_t position /**< Slave position. */
        )
{
    ec_slave_t *slave = master->slaves;
    EC_FIND_SLAVE;
}

/** Finds a slave in the bus, given the alias and position.
 *
 * Const version.
 */
const ec_slave_t *ec_master_find_slave_const(
        const ec_master_t *master, /**< EtherCAT master. */
        uint16_t alias, /**< Slave alias. */
        uint16_t position /**< Slave position. */
        )
{
    const ec_slave_t *slave = master->slaves;
    EC_FIND_SLAVE;
}

/*****************************************************************************/

/** Get the number of slave configurations provided by the application.
 *
 * \return Number of configurations.
 */
unsigned int ec_master_config_count(
        const ec_master_t *master /**< EtherCAT master. */
        )
{
    const ec_slave_config_t *sc;
    unsigned int count = 0;

    list_for_each_entry(sc, &master->configs, list) {
        count++;
    }

    return count;
}

/*****************************************************************************/

/** Common implementation for ec_master_get_config()
 * and ec_master_get_config_const().
 */
#define EC_FIND_CONFIG \
    do { \
        list_for_each_entry(sc, &master->configs, list) { \
            if (pos--) \
                continue; \
            return sc; \
        } \
        return NULL; \
    } while (0)

/** Get a slave configuration via its position in the list.
 *
 * \return Slave configuration or \a NULL.
 */
ec_slave_config_t *ec_master_get_config(
        const ec_master_t *master, /**< EtherCAT master. */
        unsigned int pos /**< List position. */
        )
{
    ec_slave_config_t *sc;
    EC_FIND_CONFIG;
}

/** Get a slave configuration via its position in the list.
 *
 * Const version.
 *
 * \return Slave configuration or \a NULL.
 */
const ec_slave_config_t *ec_master_get_config_const(
        const ec_master_t *master, /**< EtherCAT master. */
        unsigned int pos /**< List position. */
        )
{
    const ec_slave_config_t *sc;
    EC_FIND_CONFIG;
}

/*****************************************************************************/

/** Get the number of domains.
 *
 * \return Number of domains.
 */
unsigned int ec_master_domain_count(
        const ec_master_t *master /**< EtherCAT master. */
        )
{
    const ec_domain_t *domain;
    unsigned int count = 0;

    list_for_each_entry(domain, &master->domains, list) {
        count++;
    }

    return count;
}

/*****************************************************************************/

/** Common implementation for ec_master_find_domain() and
 * ec_master_find_domain_const().
 */
#define EC_FIND_DOMAIN \
    do { \
        list_for_each_entry(domain, &master->domains, list) { \
            if (index--) \
                continue; \
            return domain; \
        } \
        \
        return NULL; \
    } while (0)

/** Get a domain via its position in the list.
 *
 * \return Domain pointer, or \a NULL if not found.
 */
ec_domain_t *ec_master_find_domain(
        ec_master_t *master, /**< EtherCAT master. */
        unsigned int index /**< Domain index. */
        )
{
    ec_domain_t *domain;
    EC_FIND_DOMAIN;
}

/** Get a domain via its position in the list.
 *
 * Const version.
 *
 * \return Domain pointer, or \a NULL if not found.
 */
const ec_domain_t *ec_master_find_domain_const(
        const ec_master_t *master, /**< EtherCAT master. */
        unsigned int index /**< Domain index. */
        )
{
    const ec_domain_t *domain;
    EC_FIND_DOMAIN;
}

/*****************************************************************************/

#ifdef EC_EOE

/** Get the number of EoE handlers.
 *
 * \return Number of EoE handlers.
 */
uint16_t ec_master_eoe_handler_count(
        const ec_master_t *master /**< EtherCAT master. */
        )
{
    const ec_eoe_t *eoe;
    unsigned int count = 0;

    list_for_each_entry(eoe, &master->eoe_handlers, list) {
        count++;
    }

    return count;
}

/*****************************************************************************/

/** Get an EoE handler via its position in the list.
 *
 * Const version.
 *
 * \return EoE handler pointer, or \a NULL if not found.
 */
const ec_eoe_t *ec_master_get_eoe_handler_const(
        const ec_master_t *master, /**< EtherCAT master. */
        uint16_t index /**< EoE handler index. */
        )
{
    const ec_eoe_t *eoe;

    list_for_each_entry(eoe, &master->eoe_handlers, list) {
        if (index--)
            continue;
        return eoe;
    }

    return NULL;
}

#endif

/*****************************************************************************/

/** Set the debug level.
 *
 * \retval       0 Success.
 * \retval -EINVAL Invalid debug level.
 */
int ec_master_debug_level(
        ec_master_t *master, /**< EtherCAT master. */
        unsigned int level /**< Debug level. May be 0, 1 or 2. */
        )
{
    if (level > 2) {
        EC_MASTER_ERR(master, "Invalid debug level %u!\n", level);
        return -EINVAL;
    }

    if (level != master->debug_level) {
        master->debug_level = level;
        EC_MASTER_INFO(master, "Master debug level set to %u.\n",
                master->debug_level);
    }

    return 0;
}

/*****************************************************************************/

/** Finds the DC reference clock.
 */
void ec_master_find_dc_ref_clock(
        ec_master_t *master /**< EtherCAT master. */
        )
{
    ec_slave_t *slave, *ref = NULL;

    for (slave = master->slaves;
            slave < master->slaves + master->slave_count;
            slave++) {
        if (slave->base_dc_supported && slave->has_dc_system_time) {
            ref = slave;
            break;
        }
    }

    master->dc_ref_clock = ref;
    
    // This call always succeeds, because the datagram has been pre-allocated.
    ec_datagram_frmw(&master->sync_datagram,
            ref ? ref->station_address : 0xffff, 0x0910, 4);
}

/*****************************************************************************/

/** Calculates the bus topology; recursion function.
 */
int ec_master_calc_topology_rec(
        ec_master_t *master, /**< EtherCAT master. */
        ec_slave_t *port0_slave, /**< Slave at port 0. */
        unsigned int *slave_position /**< Slave position. */
        )
{
    ec_slave_t *slave = master->slaves + *slave_position;
    unsigned int i;
    int ret;

    slave->ports[0].next_slave = port0_slave;

    for (i = 1; i < EC_MAX_PORTS; i++) {
        if (!slave->ports[i].link.loop_closed) {
            *slave_position = *slave_position + 1;
            if (*slave_position < master->slave_count) {
                slave->ports[i].next_slave = master->slaves + *slave_position;
                ret = ec_master_calc_topology_rec(master,
                        slave, slave_position);
                if (ret)
                    return ret;
            } else {
                return -1;
            }
        }
    }

    return 0;
}

/*****************************************************************************/

/** Calculates the bus topology.
 */
void ec_master_calc_topology(
        ec_master_t *master /**< EtherCAT master. */
        )
{
    unsigned int slave_position = 0;

    if (master->slave_count == 0)
        return;

    if (ec_master_calc_topology_rec(master, NULL, &slave_position))
        EC_MASTER_ERR(master, "Failed to calculate bus topology.\n");
}

/*****************************************************************************/

/** Calculates the bus transmission delays.
 */
void ec_master_calc_transmission_delays(
        ec_master_t *master /**< EtherCAT master. */
        )
{
    ec_slave_t *slave;

    for (slave = master->slaves;
            slave < master->slaves + master->slave_count;
            slave++) {
        ec_slave_calc_port_delays(slave);
    }

    if (master->dc_ref_clock) {
        uint32_t delay = 0;
        ec_slave_calc_transmission_delays_rec(master->dc_ref_clock, &delay);
    }
}

/*****************************************************************************/

/** Distributed-clocks calculations.
 */
void ec_master_calc_dc(
        ec_master_t *master /**< EtherCAT master. */
        )
{
    // find DC reference clock
    ec_master_find_dc_ref_clock(master);

    // calculate bus topology
    ec_master_calc_topology(master);

    ec_master_calc_transmission_delays(master);
}

/*****************************************************************************/

/** Request OP state for configured slaves.
 */
void ec_master_request_op(
        ec_master_t *master /**< EtherCAT master. */
        )
{
    unsigned int i;
    ec_slave_t *slave;

    if (!master->active)
        return;

    EC_MASTER_DBG(master, 1, "Requesting OP...\n");

    // request OP for all configured slaves
    for (i = 0; i < master->slave_count; i++) {
        slave = master->slaves + i;
        if (slave->config) {
            ec_slave_request_state(slave, EC_SLAVE_STATE_OP);
        }
    }

    // always set DC reference clock to OP
    if (master->dc_ref_clock) {
        ec_slave_request_state(master->dc_ref_clock,
                EC_SLAVE_STATE_OP);
    }
}

/******************************************************************************
 *  Application interface
 *****************************************************************************/

/** Same as ecrt_master_create_domain(), but with ERR_PTR() return value.
 */
ec_domain_t *ecrt_master_create_domain_err(
        ec_master_t *master /**< master */
        )
{
    ec_domain_t *domain, *last_domain;
    unsigned int index;

    EC_MASTER_DBG(master, 1, "ecrt_master_create_domain(master = 0x%p)\n",
            master);

    if (!(domain = (ec_domain_t *) kmalloc(sizeof(ec_domain_t), GFP_KERNEL))) {
        EC_MASTER_ERR(master, "Error allocating domain memory!\n");
        return ERR_PTR(-ENOMEM);
    }

    down(&master->master_sem);

    if (list_empty(&master->domains)) {
        index = 0;
    } else {
        last_domain = list_entry(master->domains.prev, ec_domain_t, list);
        index = last_domain->index + 1;
    }

    ec_domain_init(domain, master, index);
    list_add_tail(&domain->list, &master->domains);

    up(&master->master_sem);

    EC_MASTER_DBG(master, 1, "Created domain %u.\n", domain->index);

    return domain;
}

/*****************************************************************************/

ec_domain_t *ecrt_master_create_domain(
        ec_master_t *master /**< master */
        )
{
    ec_domain_t *d = ecrt_master_create_domain_err(master);
    return IS_ERR(d) ? NULL : d;
}

/*****************************************************************************/

int ecrt_master_activate(ec_master_t *master)
{
    uint32_t domain_offset;
    ec_domain_t *domain;
    int ret;
#ifdef EC_EOE
    int eoe_was_running;
#endif

    EC_MASTER_DBG(master, 1, "ecrt_master_activate(master = 0x%p)\n", master);

    if (master->active) {
        EC_MASTER_WARN(master, "%s: Master already active!\n", __func__);
        return 0;
    }

    down(&master->master_sem);

    // finish all domains
    domain_offset = 0;
    list_for_each_entry(domain, &master->domains, list) {
        ret = ec_domain_finish(domain, domain_offset);
        if (ret < 0) {
            up(&master->master_sem);
            EC_MASTER_ERR(master, "Failed to finish domain 0x%p!\n", domain);
            return ret;
        }
        domain_offset += domain->data_size;
    }
    
    up(&master->master_sem);

    // restart EoE process and master thread with new locking

    ec_master_thread_stop(master);
#ifdef EC_EOE
    eoe_was_running = master->eoe_thread != NULL;
    ec_master_eoe_stop(master);
#endif

    EC_MASTER_DBG(master, 1, "FSM datagram is %p.\n", &master->fsm_datagram);

    master->injection_seq_fsm = 0;
    master->injection_seq_rt = 0;

    if (master->app_fsm_queue_lock_cb && master->app_fsm_queue_unlock_cb) {
        master->fsm_queue_lock_cb = master->app_fsm_queue_lock_cb;
        master->fsm_queue_unlock_cb = master->app_fsm_queue_unlock_cb;
        master->fsm_queue_locking_data = master->app_fsm_queue_locking_data;
    }

#ifdef EC_EOE
    if (eoe_was_running) {
        ec_master_eoe_start(master);
    }
#endif
    ret = ec_master_thread_start(master, ec_master_operation_thread,
                "EtherCAT-OP");
    if (ret < 0) {
        EC_MASTER_ERR(master, "Failed to start master thread!\n");
        return ret;
    }

    master->allow_scan = 1; // allow re-scanning on topology change
    master->active = 1;

    // notify state machine, that the configuration shall now be applied
    master->config_changed = 1;

    return 0;
}

/*****************************************************************************/

void ecrt_master_deactivate(ec_master_t *master)
{
    ec_slave_t *slave;
#ifdef EC_EOE
    ec_eoe_t *eoe;
    int eoe_was_running;
#endif

    EC_MASTER_DBG(master, 1, "%s(master = 0x%p)\n", __func__, master);

    if (!master->active) {
        EC_MASTER_WARN(master, "%s: Master not active.\n", __func__);
        return;
    }

    ec_master_thread_stop(master);
#ifdef EC_EOE
    eoe_was_running = master->eoe_thread != NULL;
    ec_master_eoe_stop(master);
#endif
    
    master->fsm_queue_lock_cb = ec_master_internal_lock_cb;
    master->fsm_queue_unlock_cb = ec_master_internal_unlock_cb;
    master->fsm_queue_locking_data = master;

    ec_master_clear_config(master);

    for (slave = master->slaves;
            slave < master->slaves + master->slave_count;
            slave++) {

        // set states for all slaves
        ec_slave_request_state(slave, EC_SLAVE_STATE_PREOP);

        // mark for reconfiguration, because the master could have no
        // possibility for a reconfiguration between two sequential operation
        // phases.
        slave->force_config = 1;
    }

#ifdef EC_EOE
    // ... but leave EoE slaves in OP
    list_for_each_entry(eoe, &master->eoe_handlers, list) {
        if (ec_eoe_is_open(eoe))
            ec_slave_request_state(eoe->slave, EC_SLAVE_STATE_OP);
    }
#endif

    master->app_time = 0ULL;
    master->app_start_time = 0ULL;
    master->has_app_time = 0;

#ifdef EC_EOE
    if (eoe_was_running) {
        ec_master_eoe_start(master);
    }
#endif
    if (ec_master_thread_start(master, ec_master_idle_thread,
                "EtherCAT-IDLE"))
        EC_MASTER_WARN(master, "Failed to restart master thread!\n");

    master->allow_scan = 1;
    master->active = 0;
}

/*****************************************************************************/

size_t ecrt_master_send(ec_master_t *master)
{
    ec_datagram_t *datagram, *n;

    if (master->injection_seq_rt != master->injection_seq_fsm) {
        // inject datagrams produced by master & slave FSMs
        ec_master_queue_datagram(master, &master->fsm_datagram);
        master->injection_seq_rt = master->injection_seq_fsm;
    }

    ec_master_inject_external_datagrams(master);

    if (unlikely(!master->main_device.link_state)) {
        // link is down, no datagram can be sent
        list_for_each_entry_safe(datagram, n, &master->datagram_queue, queue) {
            ec_slave_t *mbox_slave;
            uint8_t mbox_prot;
            if (ec_slave_is_mbox_datagram(datagram, EC_DATAGRAM_MAILBOX_FETCH,
                                          &mbox_slave, &mbox_prot))
                mbox_slave->tx_mailbox_filled = mbox_slave->tx_mailbox_fetching = 0;
            datagram->state = EC_DATAGRAM_ERROR;
            list_del_init(&datagram->queue);
        }

        // query link state
        ec_device_poll(&master->main_device);

        // clear frame statistics
        ec_device_clear_stats(&master->main_device);
        return 0;
    }

    // send frames
    return ec_master_send_datagrams(master);
}

/*****************************************************************************/

void ecrt_master_receive(ec_master_t *master)
{
    ec_datagram_t *datagram, *next;

    // receive datagrams
    ec_device_poll(&master->main_device);

    // dequeue all datagrams that timed out
    list_for_each_entry_safe(datagram, next, &master->datagram_queue, queue) {
        if (datagram->state != EC_DATAGRAM_SENT
            && datagram->state != EC_DATAGRAM_QUEUED)
            continue;

#ifdef EC_HAVE_CYCLES
        if (datagram->cycles_sent - master->main_device.cycles_poll
                > timeout_cycles
            && master->main_device.cycles_poll - datagram->cycles_sent
                > timeout_cycles) {
#else
        if (datagram->jiffies_sent - master->main_device.jiffies_poll
                > timeout_jiffies
            && master->main_device.jiffies_poll - datagram->jiffies_sent
                > timeout_jiffies) {
#endif
            ec_slave_t *mbox_slave;
            uint8_t mbox_prot;
            if (ec_slave_is_mbox_datagram(datagram, EC_DATAGRAM_MAILBOX_FETCH,
                                          &mbox_slave, &mbox_prot))
                mbox_slave->tx_mailbox_filled = mbox_slave->tx_mailbox_fetching = 0;
            list_del_init(&datagram->queue);
            datagram->state = EC_DATAGRAM_TIMED_OUT;
            master->stats.timeouts++;
            ec_master_output_stats(master);

            if (unlikely(master->debug_level > 0)) {
                unsigned int time_us;
#ifdef EC_HAVE_CYCLES
                time_us = (unsigned int) (master->main_device.cycles_poll -
                        datagram->cycles_sent) * 1000 / cpu_khz;
#else
                time_us = (unsigned int) ((master->main_device.jiffies_poll -
                            datagram->jiffies_sent) * 1000000 / HZ);
#endif
                EC_MASTER_DBG(master, 0, "TIMED OUT datagram %p,"
                        " index %02X waited %u us.\n",
                        datagram, datagram->index, time_us);
            }
        }
    }
}

/*****************************************************************************/

void ecrt_master_send_ext(ec_master_t *master)
{
    ec_datagram_t *datagram, *next;

    down(&master->ext_queue_sem);
    list_for_each_entry_safe(datagram, next, &master->ext_datagram_queue,
            queue) {
        list_del(&datagram->queue);
        ec_master_queue_datagram(master, datagram);
    }
    up(&master->ext_queue_sem);

    ecrt_master_send(master);
}

/*****************************************************************************/

/** Same as ecrt_master_slave_config(), but with ERR_PTR() return value.
 */
ec_slave_config_t *ecrt_master_slave_config_err(ec_master_t *master,
        uint16_t alias, uint16_t position, uint32_t vendor_id,
        uint32_t product_code)
{
    ec_slave_config_t *sc;
    unsigned int found = 0;


    EC_MASTER_DBG(master, 1, "ecrt_master_slave_config(master = 0x%p,"
            " alias = %u, position = %u, vendor_id = 0x%08x,"
            " product_code = 0x%08x)\n",
            master, alias, position, vendor_id, product_code);

    list_for_each_entry(sc, &master->configs, list) {
        if (sc->alias == alias && sc->position == position) {
            found = 1;
            break;
        }
    }

    if (found) { // config with same alias/position already existing
        if (sc->vendor_id != vendor_id || sc->product_code != product_code) {
            EC_MASTER_ERR(master, "Slave type mismatch. Slave was"
                    " configured as 0x%08X/0x%08X before. Now configuring"
                    " with 0x%08X/0x%08X.\n", sc->vendor_id, sc->product_code,
                    vendor_id, product_code);
            return ERR_PTR(-ENOENT);
        }
    } else {
        EC_MASTER_DBG(master, 1, "Creating slave configuration for %u:%u,"
                " 0x%08X/0x%08X.\n",
                alias, position, vendor_id, product_code);

        if (!(sc = (ec_slave_config_t *) kmalloc(sizeof(ec_slave_config_t),
                        GFP_KERNEL))) {
            EC_MASTER_ERR(master, "Failed to allocate memory"
                    " for slave configuration.\n");
            return ERR_PTR(-ENOMEM);
        }

        ec_slave_config_init(sc, master,
                alias, position, vendor_id, product_code);

        down(&master->master_sem);

        // try to find the addressed slave
        ec_slave_config_attach(sc);
        ec_slave_config_load_default_sync_config(sc);
        list_add_tail(&sc->list, &master->configs);

        up(&master->master_sem);
    }

    return sc;
}

/*****************************************************************************/

ec_slave_config_t *ecrt_master_slave_config(ec_master_t *master,
        uint16_t alias, uint16_t position, uint32_t vendor_id,
        uint32_t product_code)
{
    ec_slave_config_t *sc = ecrt_master_slave_config_err(master, alias,
            position, vendor_id, product_code);
    return IS_ERR(sc) ? NULL : sc;
}

/*****************************************************************************/

int ecrt_master(ec_master_t *master, ec_master_info_t *master_info)
{
    EC_MASTER_DBG(master, 1, "ecrt_master(master = 0x%p,"
            " master_info = 0x%p)\n", master, master_info);

    master_info->slave_count = master->slave_count;
    master_info->link_up = master->main_device.link_state;
    master_info->scan_busy = master->scan_busy;
    master_info->app_time = master->app_time;
    return 0;
}

/*****************************************************************************/

int ecrt_master_get_slave(ec_master_t *master, uint16_t slave_position,
        ec_slave_info_t *slave_info)
{
    const ec_slave_t *slave;
    unsigned int i;

    if (down_interruptible(&master->master_sem)) {
        return -EINTR;
    }

    slave = ec_master_find_slave_const(master, 0, slave_position);

    slave_info->position = slave->ring_position;
    slave_info->vendor_id = slave->sii.vendor_id;
    slave_info->product_code = slave->sii.product_code;
    slave_info->revision_number = slave->sii.revision_number;
    slave_info->serial_number = slave->sii.serial_number;
    slave_info->alias = slave->effective_alias;
    slave_info->current_on_ebus = slave->sii.current_on_ebus;

    for (i = 0; i < EC_MAX_PORTS; i++) {
        slave_info->ports[i].desc = slave->ports[i].desc;
        slave_info->ports[i].link.link_up = slave->ports[i].link.link_up;
        slave_info->ports[i].link.loop_closed =
            slave->ports[i].link.loop_closed;
        slave_info->ports[i].link.signal_detected =
            slave->ports[i].link.signal_detected;
        slave_info->ports[i].receive_time = slave->ports[i].receive_time;
        if (slave->ports[i].next_slave) {
            slave_info->ports[i].next_slave =
                slave->ports[i].next_slave->ring_position;
        } else {
            slave_info->ports[i].next_slave = 0xffff;
        }
        slave_info->ports[i].delay_to_next_dc =
            slave->ports[i].delay_to_next_dc;
    }

    slave_info->al_state = slave->current_state;
    slave_info->error_flag = slave->error_flag;
    slave_info->sync_count = slave->sii.sync_count;
    slave_info->sdo_count = ec_slave_sdo_count(slave);
    if (slave->sii.name) {
        strncpy(slave_info->name, slave->sii.name, EC_MAX_STRING_LENGTH);
    } else {
        slave_info->name[0] = 0;
    }

    up(&master->master_sem);

    return 0;
}

/*****************************************************************************/

void ecrt_master_callbacks(ec_master_t *master,
                           void (*lock_cb)(void *), void (*unlock_cb)(void *),
                           void *cb_data)
{
    EC_MASTER_DBG(master, 1,"ecrt_master_callbacks(master = %p, "
                            "lock_cb = %p, unlock_cb = %p, cb_data = %p)\n",
                            master, lock_cb, unlock_cb, cb_data);

    master->app_fsm_queue_lock_cb = lock_cb;
    master->app_fsm_queue_unlock_cb = unlock_cb;
    master->app_fsm_queue_locking_data = cb_data;
}

/*****************************************************************************/

void ecrt_master_state(const ec_master_t *master, ec_master_state_t *state)
{
    state->slaves_responding = master->fsm.slaves_responding;
    state->al_states = master->fsm.slave_states;
    state->link_up = master->main_device.link_state;
}

/*****************************************************************************/

void ecrt_master_application_time(ec_master_t *master, uint64_t app_time)
{
    master->app_time = app_time;

    if (unlikely(!master->has_app_time)) {
        master->app_start_time = app_time;
        master->has_app_time = 1;
    }
}

/*****************************************************************************/

void ecrt_master_sync_reference_clock(ec_master_t *master)
{
    EC_WRITE_U32(master->ref_sync_datagram.data, master->app_time);
    ec_master_queue_datagram(master, &master->ref_sync_datagram);
}

/*****************************************************************************/

void ecrt_master_sync_slave_clocks(ec_master_t *master)
{
    ec_datagram_zero(&master->sync_datagram);
    ec_master_queue_datagram(master, &master->sync_datagram);
}

/*****************************************************************************/

void ecrt_master_sync_monitor_queue(ec_master_t *master)
{
    ec_datagram_zero(&master->sync_mon_datagram);
    ec_master_queue_datagram(master, &master->sync_mon_datagram);
}

/*****************************************************************************/

uint32_t ecrt_master_sync_monitor_process(ec_master_t *master)
{
    if (master->sync_mon_datagram.state == EC_DATAGRAM_RECEIVED) {
        return EC_READ_U32(master->sync_mon_datagram.data) & 0x7fffffff;
    } else {
        return 0xffffffff;
    }
}

/*****************************************************************************/

int ecrt_master_sdo_download(ec_master_t *master, uint16_t slave_position,
        uint16_t index, uint8_t subindex, const uint8_t *data,
        size_t data_size, uint32_t *abort_code)
{
    ec_master_sdo_request_t request;
    int retval;

    EC_MASTER_DBG(master, 1, "%s(master = 0x%p,"
            " slave_position = %u, index = 0x%04X, subindex = 0x%02X,"
            " data = 0x%p, data_size = %zu, abort_code = 0x%p)\n",
            __func__, master, slave_position, index, subindex,
            data, data_size, abort_code);

    if (!data_size) {
        EC_MASTER_ERR(master, "Zero data size!\n");
        return -EINVAL;
    }

    ec_sdo_request_init(&request.req);
    ec_sdo_request_address(&request.req, index, subindex);
    if (ec_sdo_request_alloc(&request.req, data_size)) {
        ec_sdo_request_clear(&request.req);
        return -ENOMEM;
    }

    memcpy(request.req.data, data, data_size);
    request.req.data_size = data_size;
    ecrt_sdo_request_write(&request.req);

    if (down_interruptible(&master->master_sem)) {
        ec_sdo_request_clear(&request.req);
        return -EINTR;
    }

    if (!(request.slave = ec_master_find_slave(master, 0, slave_position))) {
        up(&master->master_sem);
        EC_MASTER_ERR(master, "Slave %u does not exist!\n", slave_position);
        ec_sdo_request_clear(&request.req);
        return -EINVAL;
    }

    EC_SLAVE_DBG(request.slave, 1, "Schedule SDO download request.\n");

    // schedule request.
    list_add_tail(&request.list, &request.slave->slave_sdo_requests);

    up(&master->master_sem);

    // wait for processing through FSM
    if (wait_event_interruptible(request.slave->sdo_queue,
                request.req.state != EC_INT_REQUEST_QUEUED)) {
        // interrupted by signal
        down(&master->master_sem);
        if (request.req.state == EC_INT_REQUEST_QUEUED) {
            list_del(&request.list);
            up(&master->master_sem);
            ec_sdo_request_clear(&request.req);
            return -EINTR;
        }
        // request already processing: interrupt not possible.
        up(&master->master_sem);
    }

    // wait until master FSM has finished processing
    wait_event(request.slave->sdo_queue,
            request.req.state != EC_INT_REQUEST_BUSY);

    EC_SLAVE_DBG(request.slave, 1, "Finished SDO download request.\n");

    *abort_code = request.req.abort_code;

    if (request.req.state == EC_INT_REQUEST_QUEUED)
        list_del(&request.list);

    if (request.req.state == EC_INT_REQUEST_SUCCESS) {
        retval = 0;
    } else if (request.req.errno) {
        retval = -request.req.errno;
    } else {
        retval = -EIO;
    }

    ec_sdo_request_clear(&request.req);
    return retval;
}

/*****************************************************************************/

int ecrt_master_sdo_download_complete(ec_master_t *master,
        uint16_t slave_position, uint16_t index, const uint8_t *data,
        size_t data_size, uint32_t *abort_code)
{
    ec_master_sdo_request_t request;

    EC_MASTER_DBG(master, 1, "%s(master = 0x%p,"
            " slave_position = %u, index = 0x%04X,"
            " data = 0x%p, data_size = %zu, abort_code = 0x%p)\n",
            __func__, master, slave_position, index, data, data_size,
            abort_code);

    if (!data_size) {
        EC_MASTER_ERR(master, "Zero data size!\n");
        return -EINVAL;
    }

    ec_sdo_request_init(&request.req);
    ec_sdo_request_address(&request.req, index, 0);
    if (ec_sdo_request_alloc(&request.req, data_size)) {
        ec_sdo_request_clear(&request.req);
        return -ENOMEM;
    }

    request.req.complete_access = 1;
    memcpy(request.req.data, data, data_size);
    request.req.data_size = data_size;
    ecrt_sdo_request_write(&request.req);

    if (down_interruptible(&master->master_sem))
        return -EINTR;

    if (!(request.slave = ec_master_find_slave(master, 0, slave_position))) {
        up(&master->master_sem);
        EC_MASTER_ERR(master, "Slave %u does not exist!\n", slave_position);
        ec_sdo_request_clear(&request.req);
        return -EINVAL;
    }

    EC_SLAVE_DBG(request.slave, 1, "Schedule SDO download request"
            " (complete access).\n");

    // schedule request.
    list_add_tail(&request.list, &request.slave->slave_sdo_requests);

    up(&master->master_sem);

    // wait for processing through FSM
    if (wait_event_interruptible(request.slave->sdo_queue,
                request.req.state != EC_INT_REQUEST_QUEUED)) {
        // interrupted by signal
        down(&master->master_sem);
        if (request.req.state == EC_INT_REQUEST_QUEUED) {
            list_del(&request.list);
            up(&master->master_sem);
            ec_sdo_request_clear(&request.req);
            return -EINTR;
        }
        // request already processing: interrupt not possible.
        up(&master->master_sem);
    }

    // wait until master FSM has finished processing
    wait_event(request.slave->sdo_queue,
            request.req.state != EC_INT_REQUEST_BUSY);

    EC_SLAVE_DBG(request.slave, 1, "Finished SDO download request"
            " (complete access).\n");

    *abort_code = request.req.abort_code;

    if (request.req.state == EC_INT_REQUEST_SUCCESS) {
        return 0;
    } else if (request.req.errno) {
        return -request.req.errno;
    } else {
        return -EIO;
    }
}

/*****************************************************************************/

int ecrt_master_sdo_upload(ec_master_t *master, uint16_t slave_position,
        uint16_t index, uint8_t subindex, uint8_t *target,
        size_t target_size, size_t *result_size, uint32_t *abort_code)
{
    ec_master_sdo_request_t request;
    int retval = 0;

    EC_MASTER_DBG(master, 1, "%s(master = 0x%p,"
            " slave_position = %u, index = 0x%04X, subindex = 0x%02X,"
            " target = 0x%p, target_size = %zu, result_size = 0x%p,"
            " abort_code = 0x%p)\n",
            __func__, master, slave_position, index, subindex,
            target, target_size, result_size, abort_code);

    ec_sdo_request_init(&request.req);
    ec_sdo_request_address(&request.req, index, subindex);
    ecrt_sdo_request_read(&request.req);

    if (down_interruptible(&master->master_sem)) {
        ec_sdo_request_clear(&request.req);
        return -EINTR;
    }

    if (!(request.slave = ec_master_find_slave(master, 0, slave_position))) {
        up(&master->master_sem);
        ec_sdo_request_clear(&request.req);
        EC_MASTER_ERR(master, "Slave %u does not exist!\n", slave_position);
        return -EINVAL;
    }

    EC_SLAVE_DBG(request.slave, 1, "Schedule SDO upload request.\n");

    // schedule request.
    list_add_tail(&request.list, &request.slave->slave_sdo_requests);

    up(&master->master_sem);

    // wait for processing through FSM
    if (wait_event_interruptible(request.slave->sdo_queue,
                request.req.state != EC_INT_REQUEST_QUEUED)) {
        // interrupted by signal
        down(&master->master_sem);
        if (request.req.state == EC_INT_REQUEST_QUEUED) {
            list_del(&request.list);
            up(&master->master_sem);
            ec_sdo_request_clear(&request.req);
            return -EINTR;
        }
        // request already processing: interrupt not possible.
        up(&master->master_sem);
    }

    // wait until master FSM has finished processing
    wait_event(request.slave->sdo_queue,
            request.req.state != EC_INT_REQUEST_BUSY);

    EC_SLAVE_DBG(request.slave, 1, "Finished SDO upload request.\n");

    *abort_code = request.req.abort_code;

    if (request.req.state == EC_INT_REQUEST_QUEUED)
        list_del(&request.list);

    if (request.req.state != EC_INT_REQUEST_SUCCESS) {
        *result_size = 0;
        if (request.req.errno) {
            retval = -request.req.errno;
        } else {
            retval = -EIO;
        }
    } else {
        if (request.req.data_size > target_size) {
            EC_MASTER_ERR(master, "Buffer too small.\n");
            ec_sdo_request_clear(&request.req);
            return -EOVERFLOW;
        }
        memcpy(target, request.req.data, request.req.data_size);
        *result_size = request.req.data_size;
    }

    ec_sdo_request_clear(&request.req);
    return retval;
}

/*****************************************************************************/

int ecrt_master_write_idn(ec_master_t *master, uint16_t slave_position,
        uint8_t drive_no, uint16_t idn, uint8_t *data, size_t data_size,
        uint16_t *error_code)
{
    ec_master_soe_request_t request;
    int retval;

    if (drive_no > 7) {
        EC_MASTER_ERR(master, "Invalid drive number!\n");
        return -EINVAL;
    }

    INIT_LIST_HEAD(&request.list);
    ec_soe_request_init(&request.req);
    ec_soe_request_set_drive_no(&request.req, drive_no);
    ec_soe_request_set_idn(&request.req, idn);

    if (ec_soe_request_alloc(&request.req, data_size)) {
        ec_soe_request_clear(&request.req);
        return -ENOMEM;
    }

    memcpy(request.req.data, data, data_size);
    request.req.data_size = data_size;
    ec_soe_request_write(&request.req);

    if (down_interruptible(&master->master_sem))
        return -EINTR;

    if (!(request.slave = ec_master_find_slave(
                    master, 0, slave_position))) {
        up(&master->master_sem);
        EC_MASTER_ERR(master, "Slave %u does not exist!\n",
                slave_position);
        ec_soe_request_clear(&request.req);
        return -EINVAL;
    }

    EC_SLAVE_DBG(request.slave, 1, "Scheduling SoE write request.\n");

    // schedule SoE write request.
    list_add_tail(&request.list, &request.slave->soe_requests);

    up(&master->master_sem);

    // wait for processing through FSM
    if (wait_event_interruptible(request.slave->soe_queue,
                request.req.state != EC_INT_REQUEST_QUEUED)) {
        // interrupted by signal
        down(&master->master_sem);
        if (request.req.state == EC_INT_REQUEST_QUEUED) {
            // abort request
            list_del(&request.list);
            up(&master->master_sem);
            ec_soe_request_clear(&request.req);
            return -EINTR;
        }
        up(&master->master_sem);
    }

    // wait until master FSM has finished processing
    wait_event(request.slave->soe_queue,
            request.req.state != EC_INT_REQUEST_BUSY);

    if (error_code) {
        *error_code = request.req.error_code;
    }
    retval = request.req.state == EC_INT_REQUEST_SUCCESS ? 0 : -EIO;
    ec_soe_request_clear(&request.req);

    return retval;
}

/*****************************************************************************/

int ecrt_master_read_idn(ec_master_t *master, uint16_t slave_position,
        uint8_t drive_no, uint16_t idn, uint8_t *target, size_t target_size,
        size_t *result_size, uint16_t *error_code)
{
    ec_master_soe_request_t request;

    if (drive_no > 7) {
        EC_MASTER_ERR(master, "Invalid drive number!\n");
        return -EINVAL;
    }

    INIT_LIST_HEAD(&request.list);
    ec_soe_request_init(&request.req);
    ec_soe_request_set_drive_no(&request.req, drive_no);
    ec_soe_request_set_idn(&request.req, idn);
    ec_soe_request_read(&request.req);

    if (down_interruptible(&master->master_sem))
        return -EINTR;

    if (!(request.slave = ec_master_find_slave(master, 0, slave_position))) {
        up(&master->master_sem);
        ec_soe_request_clear(&request.req);
        EC_MASTER_ERR(master, "Slave %u does not exist!\n", slave_position);
        return -EINVAL;
    }

    // schedule request.
    list_add_tail(&request.list, &request.slave->soe_requests);

    up(&master->master_sem);

    EC_SLAVE_DBG(request.slave, 1, "Scheduled SoE read request.\n");

    // wait for processing through FSM
    if (wait_event_interruptible(request.slave->soe_queue,
                request.req.state != EC_INT_REQUEST_QUEUED)) {
        // interrupted by signal
        down(&master->master_sem);
        if (request.req.state == EC_INT_REQUEST_QUEUED) {
            list_del(&request.list);
            up(&master->master_sem);
            ec_soe_request_clear(&request.req);
            return -EINTR;
        }
        // request already processing: interrupt not possible.
        up(&master->master_sem);
    }

    // wait until master FSM has finished processing
    wait_event(request.slave->soe_queue,
            request.req.state != EC_INT_REQUEST_BUSY);

    if (error_code) {
        *error_code = request.req.error_code;
    }

    EC_SLAVE_DBG(request.slave, 1, "Read %zd bytes via SoE.\n",
            request.req.data_size);

    if (request.req.state != EC_INT_REQUEST_SUCCESS) {
        if (result_size) {
            *result_size = 0;
        }
        ec_soe_request_clear(&request.req);
        return -EIO;
    } else {
        if (request.req.data_size > target_size) {
            EC_MASTER_ERR(master, "Buffer too small.\n");
            ec_soe_request_clear(&request.req);
            return -EOVERFLOW;
        }
        if (result_size) {
            *result_size = request.req.data_size;
        }
        memcpy(target, request.req.data, request.req.data_size);
        return 0;
    }
}

/*****************************************************************************/

void ecrt_master_reset(ec_master_t *master)
{
    ec_slave_config_t *sc;

    list_for_each_entry(sc, &master->configs, list) {
        if (sc->slave) {
            ec_slave_request_state(sc->slave, EC_SLAVE_STATE_OP);
        }
    }
}

/*****************************************************************************/

/** \cond */

EXPORT_SYMBOL(ecrt_master_create_domain);
EXPORT_SYMBOL(ecrt_master_activate);
EXPORT_SYMBOL(ecrt_master_deactivate);
EXPORT_SYMBOL(ecrt_master_send);
EXPORT_SYMBOL(ecrt_master_send_ext);
EXPORT_SYMBOL(ecrt_master_receive);
EXPORT_SYMBOL(ecrt_master_callbacks);
EXPORT_SYMBOL(ecrt_master);
EXPORT_SYMBOL(ecrt_master_get_slave);
EXPORT_SYMBOL(ecrt_master_slave_config);
EXPORT_SYMBOL(ecrt_master_state);
EXPORT_SYMBOL(ecrt_master_application_time);
EXPORT_SYMBOL(ecrt_master_sync_reference_clock);
EXPORT_SYMBOL(ecrt_master_sync_slave_clocks);
EXPORT_SYMBOL(ecrt_master_sync_monitor_queue);
EXPORT_SYMBOL(ecrt_master_sync_monitor_process);
EXPORT_SYMBOL(ecrt_master_sdo_download);
EXPORT_SYMBOL(ecrt_master_sdo_download_complete);
EXPORT_SYMBOL(ecrt_master_sdo_upload);
EXPORT_SYMBOL(ecrt_master_write_idn);
EXPORT_SYMBOL(ecrt_master_read_idn);
EXPORT_SYMBOL(ecrt_master_reset);

/** \endcond */

/*****************************************************************************/
