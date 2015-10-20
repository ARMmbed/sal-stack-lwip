/*
 * Copyright (c) 2012-2015, ARM Limited, All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __ARCH_SYS_ARCH_H__
#define __ARCH_SYS_ARCH_H__

#include "lwip/opt.h"

#if NO_SYS == 0
#include "cmsis_os.h"

// === SEMAPHORE ===
typedef struct {
    osSemaphoreId    id;
    osSemaphoreDef_t def;
#ifdef CMSIS_OS_RTX
    uint32_t         data[2];
#endif
} sys_sem_t;

#define sys_sem_valid(x)        (((*x).id == NULL) ? 0 : 1)
#define sys_sem_set_invalid(x)  ( (*x).id = NULL)

// === MUTEX ===
typedef struct {
    osMutexId    id;
    osMutexDef_t def;
#ifdef CMSIS_OS_RTX
    int32_t      data[3];
#endif
} sys_mutex_t;

// === MAIL BOX ===
#define MB_SIZE      8

typedef struct {
    osMessageQId    id;
    osMessageQDef_t def;
#ifdef CMSIS_OS_RTX
    uint32_t        queue[4+MB_SIZE]; /* The +4 is required for RTX OS_MCB overhead. */
#endif
} sys_mbox_t;

#define SYS_MBOX_NULL               ((uint32_t) NULL)
#define sys_mbox_valid(x)           (((*x).id == NULL) ? 0 : 1 )
#define sys_mbox_set_invalid(x)     ( (*x).id = NULL )

#if ((DEFAULT_RAW_RECVMBOX_SIZE) > (MB_SIZE)) || \
    ((DEFAULT_UDP_RECVMBOX_SIZE) > (MB_SIZE)) || \
    ((DEFAULT_TCP_RECVMBOX_SIZE) > (MB_SIZE)) || \
    ((DEFAULT_ACCEPTMBOX_SIZE)   > (MB_SIZE)) || \
    ((TCPIP_MBOX_SIZE)           > (MB_SIZE))
#   error Mailbox size not supported
#endif

// === THREAD ===
typedef struct {
    osThreadId    id;
    osThreadDef_t def;
} sys_thread_data_t;
typedef sys_thread_data_t* sys_thread_t;

#define SYS_THREAD_POOL_N                   6
#define SYS_DEFAULT_THREAD_STACK_DEPTH      DEFAULT_STACK_SIZE

// === PROTECTION ===
typedef int sys_prot_t;

#else
#ifdef  __cplusplus
extern "C" {
#endif

/** \brief  Init systick to 1ms rate
 *
 *  This init the systick to 1ms rate. This function is only used in standalone
 *  systems.
 */
void SysTick_Init(void);


/** \brief  Get the current systick time in milliSeconds
 *
 *  Returns the current systick time in milliSeconds. This function is only
 *  used in standalone systems.
 *
 *  /returns current systick time in milliSeconds
 */
uint32_t SysTick_GetMS(void);

/** \brief  Delay for the specified number of milliSeconds
 *
 *  For standalone systems. This function will block for the specified
 *  number of milliSconds. For RTOS based systems, this function will delay
 *  the task by the specified number of milliSeconds.
 *
 *  \param[in]  ms Time in milliSeconds to delay
 */
void osDelay(uint32_t ms);

#ifdef  __cplusplus
}
#endif
#endif

#endif /* __ARCH_SYS_ARCH_H__ */
