/* ----------------------------------------------------------------------------
 *         ATMEL Microcontroller Software Support 
 * ----------------------------------------------------------------------------
 * Copyright (c) 2008, Atmel Corporation
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the disclaimer below.
 *
 * Atmel's name may not be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * DISCLAIMER: THIS SOFTWARE IS PROVIDED BY ATMEL "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
 * DISCLAIMED. IN NO EVENT SHALL ATMEL BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * ----------------------------------------------------------------------------
 */

//------------------------------------------------------------------------------
//         Headers
//------------------------------------------------------------------------------

#include "AUDDLoopRecDriver.h"
#include "AUDDLoopRecDriverDescriptors.h"
#include "AUDDLoopRecChannel.h"
#include <utility/trace.h>
#include <utility/led.h>
#include <usb/common/audio/AUDGenericRequest.h>
#include <usb/common/audio/AUDFeatureUnitRequest.h>
#include <usb/device/core/USBDDriver.h>

//------------------------------------------------------------------------------
//         Internal types
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/// Audio LoopRec driver internal state.
//------------------------------------------------------------------------------
typedef struct {

    /// USB device driver instance.
    USBDDriver usbdDriver;
    /// List of AUDDLoopRecChannel instances for playback.
    AUDDLoopRecChannel channels[AUDDLoopRecDriver_NUMCHANNELS+1];
    /// List of AUDDLoopRecChannel instances for record.
    AUDDLoopRecChannel recChannels[1];

} AUDDLoopRecDriver;

//------------------------------------------------------------------------------
//         Internal variables
//------------------------------------------------------------------------------

/// Global USB audio LoopRec driver instance.
static AUDDLoopRecDriver auddLoopRecDriver;
/// Array for storing the current setting of each interface.
static unsigned char auddLoopRecDriverInterfaces[2];
/// Intermediate storage variable for the mute status of a channel.
static unsigned char muted;

//------------------------------------------------------------------------------
//         Internal functions
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/// Callback triggered after the new mute status of a channel has been read
/// by AUDDLoopRecDriver_SetFeatureCurrentValue. Changes the mute status
/// of the given channel accordingly.
/// \param channel Number of the channel whose mute status has changed.
//------------------------------------------------------------------------------
static void AUDDLoopRecDriver_MuteReceived(unsigned int channel)
{
    AUDDLoopRecChannel * pChannel;
    if ((unsigned char)(channel >> 8) ==
         AUDDLoopRecDriverDescriptors_OUTPUTTERMINAL_REC) {
        pChannel = &auddLoopRecDriver.recChannels[0];
    }
    else {
        pChannel = &auddLoopRecDriver.channels[channel];
    }
    if (muted) {
    
        AUDDLoopRecChannel_Mute(pChannel);
    }
    else {

        AUDDLoopRecChannel_Unmute(pChannel);
    }

    USBD_Write(0, 0, 0, 0, 0);
}

//------------------------------------------------------------------------------
/// Sets the current value of a particular Feature control of a channel.
/// \param entity Entity number.
/// \param channel Channel number.
/// \param control Control selector value (see TODO).
/// \param length Length of the data containing the new value.
//------------------------------------------------------------------------------
static void AUDDLoopRecDriver_SetFeatureCurrentValue(unsigned char entity,
                                                     unsigned char channel,
                                                     unsigned char control,
                                                     unsigned short length)
{
    TRACE_INFO_WP("sFeature ");
    TRACE_DEBUG("\b(E%d, CS%d, CN%d, L%d) ",
                           entity, control, channel, length);

    // Check the the requested control is supported
    // Control/channel combination not supported
    if ((control != AUDFeatureUnitRequest_MUTE) ||
        (length  != 1) ||
        ((entity == AUDDLoopRecDriverDescriptors_OUTPUTTERMINAL) &&
         (channel > AUDDLoopRecDriver_NUMCHANNELS)) ||
        ((entity == AUDDLoopRecDriverDescriptors_OUTPUTTERMINAL_REC) &&
         (channel > 0))) {

        USBD_Stall(0);
    }
    // Mute control on master channel / speakerphone
    else {

        unsigned int argument = channel | (entity << 8);
        USBD_Read(0, // Endpoint #0
                  &muted,
                  sizeof(muted),
                  (TransferCallback) AUDDLoopRecDriver_MuteReceived,
                  (void *) argument);
    }
}

//------------------------------------------------------------------------------
/// Sends the current value of a particular channel Feature to the USB host.
/// \param entity Entity number.
/// \param channel Channel number.
/// \param control Control selector value (see TODO).
/// \param length Length of the data to return.
//------------------------------------------------------------------------------
static void AUDDLoopRecDriver_GetFeatureCurrentValue(unsigned char entity,
                                                     unsigned char channel,
                                                     unsigned char control,
                                                     unsigned char length)
{
    TRACE_INFO_WP("gFeature ");
    TRACE_DEBUG("\b(CS%d, CN%d, L%d) ", control, channel, length);

    // Check that the requested control is supported
    // Master channel mute control
    if ((control == AUDFeatureUnitRequest_MUTE)
        && (channel < (AUDDLoopRecDriver_NUMCHANNELS+1))
        && (length == 1)) {

        if (entity == AUDDLoopRecDriverDescriptors_FEATUREUNIT) {
            muted = auddLoopRecDriver.channels[channel].muted;
        }
        else {
            muted = auddLoopRecDriver.recChannels[0].muted;
        }
        USBD_Write(0, &muted, sizeof(muted), 0, 0);
    }
    else {

        USBD_Stall(0);
    }
}

///*
//    Function: AUDDLoopRecDriver_SetInterface
//        Changes the current active alternate setting of the given interface.
//
//    Parameters:
//        
//*/
//TRACE_DEBUG_M("SetInterface(%d,%d) ", setup->wIndex, setup->wValue);
//
//            /* Check that interface is AudioStreaming OUT */
//            if (setup->wIndex == INTERFACE_ID_AUDIOSTREAMING_OUT) {
//
//                /* Check desired alternate setting */
//                switch (setup->wValue) {
//                    case 0:
//                    case 1:
//                        if (LoopRecDriver->isOutStreamEnabled != setup->wValue) {
//                        
//                            LoopRecDriver->isOutStreamEnabled = setup->wValue;
//                            SPK_OutStreamStatusChanged(LoopRecDriver);
//                            LED_SetGlowing(LED_OTHER, setup->wValue);
//                        }
//                        USB_SendZLP0(usbDriver, 0, 0);
//                        break;
//
//                    default:
//                        USB_Stall(usbDriver, 0);
//                }
//            }
//            else {
//
//                USB_Stall(usbDriver, 0);
//            }
//

//------------------------------------------------------------------------------
//         Callback re-implementation
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/// Triggered when the USB host emits a new SETUP request. The request is
/// forward to <AUDDLoopRecDriver_RequestHandler>.
/// \param request Pointer to a USBGenericRequest instance.
//------------------------------------------------------------------------------
#if !defined(NOAUTOCALLBACK)
void USBDCallbacks_RequestReceived(const USBGenericRequest *request)
{
    AUDDLoopRecDriver_RequestHandler(request);
}
#endif

//------------------------------------------------------------------------------
/// Invoked whenever the active setting of an interface is changed by the
/// host. Changes the status of the third LED accordingly.
/// \param interface Interface number.
/// \param setting Newly active setting.
//------------------------------------------------------------------------------
void USBDDriverCallbacks_InterfaceSettingChanged(unsigned char interface,
                                                 unsigned char setting)
{
    if ((interface == AUDDLoopRecDriverDescriptors_STREAMING)
        && (setting == 0)) {

        LED_Clear(USBD_LEDOTHER);
    }
    else {

        LED_Set(USBD_LEDOTHER);
    }
}

//------------------------------------------------------------------------------
//         Exported functions
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/// Initializes an USB audio LoopRec device driver, as well as the underlying
/// USB controller.
//------------------------------------------------------------------------------
void AUDDLoopRecDriver_Initialize()
{
    // Initialize LoopRec channels
    AUDDLoopRecChannel_Initialize(&(auddLoopRecDriver.channels[0]),
                                  AUDDLoopRecDriver_MASTERCHANNEL,
                                  0);
    AUDDLoopRecChannel_Initialize(&(auddLoopRecDriver.channels[1]),
                                  AUDDLoopRecDriver_LEFTCHANNEL,
                                  0);
    AUDDLoopRecChannel_Initialize(&(auddLoopRecDriver.channels[2]),
                                  AUDDLoopRecDriver_RIGHTCHANNEL,
                                  0);
    AUDDLoopRecChannel_Initialize(&(auddLoopRecDriver.recChannels[0]),
                                  AUDDLoopRecDriver_RECCHANNEL,
                                  0);
    
    // Initialize the USB driver
    USBDDriver_Initialize(&(auddLoopRecDriver.usbdDriver),
                          &auddLoopRecDriverDescriptors,
                          auddLoopRecDriverInterfaces);
    USBD_Init();

    // Initialize the third LED to indicate when the audio interface is active
    LED_Configure(USBD_LEDOTHER);
}

//------------------------------------------------------------------------------
/// Handles audio-specific USB requests sent by the host, and forwards
/// standard ones to the USB device driver.
/// \param request Pointer to a USBGenericRequest instance.
//------------------------------------------------------------------------------
void AUDDLoopRecDriver_RequestHandler(const USBGenericRequest *request)
{
    unsigned char entity;
    unsigned char interface;

    TRACE_INFO_WP("NewReq ");

    // Check if this is a class request
    if (USBGenericRequest_GetType(request) == USBGenericRequest_CLASS) {

        // Check if the request is supported
        switch (USBGenericRequest_GetRequest(request)) {

            case AUDGenericRequest_SETCUR:
                TRACE_INFO_WP(
                          "sCur(0x%04X) ",
                          USBGenericRequest_GetIndex(request));
    
                // Check the target interface and entity
                entity = AUDGenericRequest_GetEntity(request);
                interface = AUDGenericRequest_GetInterface(request);
                if (((entity == AUDDLoopRecDriverDescriptors_FEATUREUNIT)
                    ||(entity == AUDDLoopRecDriverDescriptors_FEATUREUNIT_REC))
                    && (interface == AUDDLoopRecDriverDescriptors_CONTROL)) {

                    AUDDLoopRecDriver_SetFeatureCurrentValue(
                        entity,
                        AUDFeatureUnitRequest_GetChannel(request),
                        AUDFeatureUnitRequest_GetControl(request),
                        USBGenericRequest_GetLength(request));
                }
                else {
    
                    TRACE_WARNING(
                              "AUDDLoopRecDriver_RequestHandler: Unsupported entity/interface combination (0x%04X)\n\r",
                              USBGenericRequest_GetIndex(request));
                    USBD_Stall(0);
                }
                break;
    
            case AUDGenericRequest_GETCUR:
                TRACE_INFO_WP(
                          "gCur(0x%04X) ",
                          USBGenericRequest_GetIndex(request));
    
                // Check the target interface and entity
                entity = AUDGenericRequest_GetEntity(request);
                interface = AUDGenericRequest_GetInterface(request);
                if (((entity == AUDDLoopRecDriverDescriptors_FEATUREUNIT)
                    ||(entity == AUDDLoopRecDriverDescriptors_FEATUREUNIT_REC))
                    && (interface == AUDDLoopRecDriverDescriptors_CONTROL)) {
    
                    AUDDLoopRecDriver_GetFeatureCurrentValue(
                        entity,
                        AUDFeatureUnitRequest_GetChannel(request),
                        AUDFeatureUnitRequest_GetControl(request),
                        USBGenericRequest_GetLength(request));
                }
                else {
    
                    TRACE_WARNING(
                              "AUDDLoopRecDriver_RequestHandler: Unsupported entity/interface combination (0x%04X)\n\r",
                              USBGenericRequest_GetIndex(request));
                    USBD_Stall(0);
                }
                break;
    
            default:
    
                TRACE_WARNING(
                          "AUDDLoopRecDriver_RequestHandler: Unsupported request (%d)\n\r",
                          USBGenericRequest_GetRequest(request));
                USBD_Stall(0);
        }
    }
    // Check if this is a standard request
    else if (USBGenericRequest_GetType(request) == USBGenericRequest_STANDARD) {

        // Forward request to the standard handler
        USBDDriver_RequestHandler(&(auddLoopRecDriver.usbdDriver), request);
    }
    // Unsupported request type
    else {

        TRACE_WARNING(
                  "AUDDLoopRecDriver_RequestHandler: Unsupported request type (%d)\n\r",
                  USBGenericRequest_GetType(request));
        USBD_Stall(0);
    }
}

//------------------------------------------------------------------------------
/// Reads incoming audio data sent by the USB host into the provided
/// buffer. When the transfer is complete, an optional callback function is
/// invoked.
/// \param buffer Pointer to the data storage buffer.
/// \param length Size of the buffer in bytes.
/// \param callback Optional callback function.
/// \param argument Optional argument to the callback function.
/// \return USBD_STATUS_SUCCESS if the transfer is started successfully;
///         otherwise an error code.
//------------------------------------------------------------------------------
unsigned char AUDDLoopRecDriver_Read(void *buffer,
                                     unsigned int length,
                                     TransferCallback callback,
                                     void *argument)
{
    return USBD_Read(AUDDLoopRecDriverDescriptors_DATAOUT,
                     buffer,
                     length,
                     callback,
                     argument);
}

//------------------------------------------------------------------------------
/// Start sending audio data sending .
/// When the transfer is complete, an optional callback function is
/// invoked.
/// \param buffer Pointer to the data storage buffer.
/// \param length Size of the buffer in bytes.
/// \param callback Optional callback function.
/// \param argument Optional argument to the callback function.
/// \return USBD_STATUS_SUCCESS if the transfer is started successfully;
///         otherwise an error code.
//------------------------------------------------------------------------------
unsigned char AUDDLoopRecDriver_Write(void *buffer,
                                      unsigned int length,
                                      TransferCallback callback,
                                      void *argument)
{
    return USBD_Write(AUDDLoopRecDriverDescriptors_DATAIN,
                      buffer,
                      length,
                      callback,
                      argument);
}