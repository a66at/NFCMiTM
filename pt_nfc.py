#!/usr/bin/python

import sys, struct
import ctypes
import ctypes.util
import nfc_ctypes
from pyHex.hexfind import hexdump, hexbytes

_lib = nfc_ctypes.lib_nfc

(NC_PN531, NC_PN532, NC_PN533) = (0x10, 0x20, 0x30)

_byte_t = ctypes.c_ubyte
_size_t = ctypes.c_size_t
_enum_val = ctypes.c_int

context = ctypes.POINTER(nfc_ctypes.nfc_context)()
_lib.nfc_init(ctypes.byref(context))

# From rfidiot
MAX_FRAME_LEN = 264
MAX_DEVICES = 16
BUFSIZ = 8192
MAX_TARGET_COUNT = 1

DEVICE_NAME_LENGTH = 256
DEVICE_PORT_LENGTH = 64
NFC_CONNSTRING_LENGTH = 1024


class NFC_CONNSTRING(ctypes.Structure):
    _pack_ = 1
    _fields_ = [('connstring', ctypes.c_ubyte * NFC_CONNSTRING_LENGTH)]


NFC_DEVICE_LIST = NFC_CONNSTRING * MAX_DEVICES


def nfc_exit():
    _lib.nfc_init(ctypes.byref(context))


# from pynfc - old
def get_version():
    res = _lib.nfc_version()
    return res


def list_devices(verbose=False):
    # max_device_length = 16
    Devices = NFC_DEVICE_LIST()
    # pnddDevices = Devices()
    num_devices = _size_t(0)
    # _lib.nfc_list_devices(pnddDevices, max_device_length, ctypes.byref(num_devices))
    num_devices = _lib.nfc_list_devices(context, ctypes.byref(Devices), MAX_DEVICES)
    result = []
    # for i in range(min(num_devices.value, MAX_DEVICES)):
    for i in range(num_devices):
        result.append(Devices[i])
    if verbose:
        print 'LibNFC ver', _lib.nfc_version(), 'devices (%d):' % num_devices
        for i in range(num_devices):
            dev = _lib.nfc_open(context, ctypes.byref(result[i]))
            devname = _lib.nfc_device_get_name(dev)
            print '    No: %d\t\t%s' % (i, devname)
    return result


class NfcDevice(object):
    NDO_HANDLE_CRC = 0x00
    NDO_HANDLE_PARITY = 0x01
    NDO_ACTIVATE_FIELD = 0x10
    NDO_ACTIVATE_CRYPTO1 = 0x11
    NDO_INFINITE_SELECT = 0x20
    NDO_ACCEPT_INVALID_FRAMES = 0x30
    NDO_ACCEPT_MULTIPLE_FRAMES = 0x31
    NDO_AUTO_ISO14443_4 = 0x40
    NDO_EASY_FRAMING = 0x41
    NDO_FORCE_ISO14443_A = 0x42

    NMT_ISO14443A = 0x0
    NMT_ISO14443B = 0x1
    NMT_FELICA = 0x2
    NMT_JEWEL = 0x3
    NMT_DEP = 0x4

    NBR_UNDEFINED = 0x0
    NBR_106 = 0x01
    NBR_212 = 0x02
    NBR_424 = 0x03
    NBR_847 = 0x04

    NDM_UNDEFINED = 0x0
    NDM_PASSIVE = 0x01
    NDM_ACTIVE = 0x02

    def __init__(self, devdesc=None, verbosity=0):
        self._device = _lib.nfc_open(context, ctypes.byref(devdesc))
        self._device_name = _lib.nfc_device_get_name(self._device)
        # print _lib.nfc_device_set_property_int(self._device, nfc_ctypes.NP_TIMEOUT_COMMAND, 500);
        # print _lib.nfc_device_set_property_int(self._device, nfc_ctypes.NP_TIMEOUT_ATR, 500);
        # print _lib.nfc_device_set_property_int(self._device, nfc_ctypes.NP_TIMEOUT_COM, 250);
        # print _lib.nfc_device_set_property_bool(self._device, nfc_ctypes.NP_HANDLE_CRC, False);
        # print _lib.nfc_device_set_property_bool(self._device, nfc_ctypes.NP_HANDLE_PARITY, False);
        # print _lib.nfc_device_set_property_bool(self._device, nfc_ctypes.NP_INFINITE_SELECT, True);
        # print _lib.nfc_device_set_property_bool(self._device, nfc_ctypes.NP_ACCEPT_INVALID_FRAMES, True);
        # print _lib.nfc_device_set_property_bool(self._device, nfc_ctypes.NP_ACCEPT_MULTIPLE_FRAMES, True);
        # print _lib.nfc_device_set_property_bool(self._device, nfc_ctypes.NP_AUTO_ISO14443_4, True);
        # # print _lib.nfc_device_set_property_bool(self._device, nfc_ctypes.NP_EASY_FRAMING, True);
        # print _lib.nfc_device_set_property_bool(self._device, nfc_ctypes.NP_FORCE_ISO14443_A, True);
        # print _lib.nfc_device_set_property_bool(self._device, nfc_ctypes.NP_FORCE_SPEED_106, True);


        # Create the buffers so that we don't have to inefficiently recreate them each call
        self._txbytes = (_byte_t * (MAX_FRAME_LEN * 8))()
        self._txpbytes = (_byte_t * (MAX_FRAME_LEN * 8))()
        self._rxbytes = (_byte_t * (MAX_FRAME_LEN * 8))()
        self._rxpbytes = (_byte_t * (MAX_FRAME_LEN * 8))()
        self.verbosity = verbosity

    def _check_enum(self, prefix, value):
        if value not in [getattr(self, i) for i in dir(self) if i.startswith(prefix)]:
            raise AttributeError("Failed to locate appropriate configuration option")

    def configure(self, option, value):
        """Configures the NFC device options"""
        # self._check_enum('NDO', option)
        return _lib.nfc_device_set_property_bool(self._device, option, value);
        # return _lib.nfc_configure(self._device, option, value)

    def initiator_init(self):
        """Initializes the NFC device for initiator"""
        return _lib.nfc_initiator_init(self._device)

    def initiator_select_passive_target(self, modtype, baudrate, initdata=None):
        """Selects a passive target"""
        # self._check_enum('NMT', modtype)
        # self._check_enum('NBR', baudrate)

        mod = nfc_ctypes.nfc_modulation(nmt=modtype, nbr=baudrate)

        if not initdata:
            data = None
            data_len = 0
        else:
            Data = ctypes.c_ubyte * len(initdata)
            data = ctypes.byref(Data.from_buffer_copy(initdata))
            data_len = len(initdata)

        # target_info = nfc_ctypes.nfc_target_info(nfc_ctypes.target_nfc_iso14443a_info)
        target = nfc_ctypes.nfc_target()
        _lib.nfc_initiator_select_passive_target(self._device,
                                                 mod,
                                                 data,
                                                 data_len,
                                                 ctypes.pointer(target))
        return target

    def initiator_list_passive_targets(self, modtype, baudrate):
        """Lists all available passive targets"""
        # self._check_enum('NMT', modtype)
        # self._check_enum('NBR', baudrate)

        mod = nfc_ctypes.nfc_modulation(nmt=modtype, nbr=baudrate)

        max_targets_length = 16
        Targets = nfc_ctypes.nfc_target * max_targets_length
        targets = Targets()
        # num_targets = _size_t(0)

        num_targets = _lib.nfc_initiator_list_passive_targets(self._device,
                                                              mod,
                                                              ctypes.byref(targets),
                                                              max_targets_length)
        # ctypes.byref(num_targets))

        result = []
        for i in range(num_targets):
            result.append(targets[i])
        return result

    def initiator_deselect_target(self):
        """Deselects any selected target"""
        return _lib.nfc_initiator_deselect_target(self._device)

    def initiator_select_dep_target(self, depmode, baudrate, depinfo):
        """Selects a dep target"""
        self._check_enum('NDM', depmode)
        self._check_enum('NBR', baudrate)

        if not depinfo:
            data = None
        else:
            data = ctypes.byref(depinfo)

        target = nfc_ctypes.nfc_target()
        _lib.nfc_initiator_select_dep_target(self._device,
                                             depmode,
                                             baudrate,
                                             data,
                                             ctypes.byref(target))
        return target

    def initiator_poll_targets(self, targetlist, pollnum, period):

        # targtypes = Modulation * len(targetlist)
        targtypes = nfc_ctypes.nfc_modulation * len(targetlist)
        for i in range(len(targetlist)):
            targtypes[i] = targetlist[i]

        max_targets_length = 16
        # Targets = Target * max_targets_length
        Targets = nfc_ctypes.nfc_target * max_targets_length
        targets = Targets()
        num_targets = _size_t(0)
        _lib.nfc_initiator_poll_targets(self._device, ctypes.byref(targtypes),
                                        _size_t(len(targetlist)),
                                        _byte_t(pollnum),
                                        _byte_t(period),
                                        ctypes.byref(targets),
                                        ctypes.byref(num_targets))
        result = []
        for i in range(min(num_targets.value, max_targets_length)):
            result.append(targets[i])
        return result

    def initiator_transceive_bits(self, bits, numbits, paritybits=None):
        """Sends a series of bits, returning the number and bits sent back by the target"""
        if paritybits and len(paritybits) != len(bits):
            raise ValueError("Length of parity bits does not match length of bits")
        if len(bits) < ((numbits + 7) / 8):
            raise ValueError("Length of bits does not match the value passed in numbits")

        insize = ((numbits + 7) / 8)
        for i in range(insize):
            self._txbytes[i] = ord(bits[i])
            if paritybits:
                self._txpbytes[i] = ord(paritybits[i]) & 0x01

        parity = None
        if paritybits:
            parity = ctypes.pointer(self._txpbytes)

        # rxbitlen = _size_t(0)

        rxbitlen = _lib.nfc_initiator_transceive_bits(self._device,
                                                      ctypes.pointer(self._txbytes),
                                                      _size_t(numbits),
                                                      parity,
                                                      ctypes.pointer(self._rxbytes),
                                                      MAX_FRAME_LEN,
                                                      ctypes.pointer(self._rxpbytes))
        # if not result:
        #     return None

        rxbytes = rxpbytes = ""
        for i in range((rxbitlen + 7) / 8):
            rxbytes += chr(self._rxbytes[i])
            rxpbytes += chr(self._rxpbytes[i])

        return rxbytes, rxbitlen, rxpbytes

    def initiator_transceive_bytes(self, inbytes):
        """Sends a series of bytes, returning those bytes sent back by the target"""
        if self.verbosity > 0: print 'R>T[%2X]: %s' % (len(inbytes), hexbytes(inbytes))
        insize = len(inbytes)
        for i in range(insize):
            self._txbytes[i] = ord(inbytes[i])

        rxbytelen = _lib.nfc_initiator_transceive_bytes(self._device,
                                                        ctypes.byref(self._txbytes),
                                                        _size_t(insize),
                                                        ctypes.byref(self._rxbytes),
                                                        MAX_FRAME_LEN,
                                                        -1)

        if not rxbytelen >= 0:
            if self.verbosity > 0: print 'T%2X[--]:' % (rxbytelen)
            return "", rxbytelen

        if self.verbosity > 0: print 'T%2X[%2X]: %s' % (
            rxbytelen, rxbytelen.value, hexbytes(buffer(self._rxbytes)[:rxbytelen.value]))

        result = ""
        for i in range(rxbytelen):
            result += chr(self._rxbytes[i])

        return result, rxbytelen

    def get_error(self):
        """Returns an error description for any error that may have occurred from the previous command"""
        return _lib.nfc_strerror(self._device)

    def target_init(self, targettype=None):
        """Initializes the device as a target"""
        rxsize = _size_t(0)

        if targettype:
            targettype = ctypes.byref(targettype)

        return _lib.nfc_target_init(self._device,
                                    targettype,
                                    ctypes.byref(self._rxbytes),
                                    ctypes.byref(rxsize),
                                    0)

    def target_receive_bits(self):
        """Receives bits and parity bits from a device in target mode"""
        # rxsize = _size_t(0)
        rxsize = _lib.nfc_target_receive_bits(self._device,
                                              ctypes.byref(self._rxbytes),
                                              MAX_FRAME_LEN,
                                              ctypes.byref(self._rxpbytes))

        if not rxsize >= 0:
            print ""
            return "", rxsize, ""

        rxbytes = rxpbytes = ""
        for i in range((rxsize + 7) / 8):
            rxbytes += chr(self._rxbytes[i])
            rxpbytes += chr(self._rxpbytes[i])

        return rxbytes, rxsize, rxpbytes

    def target_receive_bytes(self):
        """Receives bytes from a device in target mode"""
        # rxsize = _size_t(0)
        rxsize = _lib.nfc_target_receive_bytes(self._device,
                                               ctypes.byref(self._rxbytes),
                                               MAX_FRAME_LEN,
                                               0)

        if not rxsize >= 0:
            return "", rxsize

        result = ""
        for i in range(rxsize):
            result += chr(self._rxbytes[i])
        return result, rxsize

    def target_send_bits(self, bits, numbits, paritybits=None):
        """Sends bits and paritybits in target mode"""
        if paritybits and len(paritybits) != len(bits):
            raise ValueError("Length of parity bits does not match length of bits")
        if len(bits) < ((numbits + 7) / 8):
            raise ValueError("Length of bits does not match the value passed in numbits")

        insize = ((numbits + 7) / 8)
        for i in range(insize):
            self._txbytes[i] = ord(bits[i])
            if paritybits:
                self._txpbytes[i] = ord(paritybits[i]) & 0x01

        parity = None
        if paritybits:
            parity = ctypes.byref(self._txpbytes)

        return _lib.nfc_target_send_bits(self._device,
                                         ctypes.byref(self._txbytes),
                                         numbits,
                                         parity)

    def target_send_bytes(self, inbytes):
        """Sends bytes in target mode"""
        insize = min(len(inbytes), MAX_FRAME_LEN)
        for i in range(insize):
            self._txbytes[i] = ord(inbytes[i])

        return _lib.nfc_target_send_bytes(self._device,
                                          ctypes.byref(self._txbytes),
                                          _size_t(insize),
                                          0)


class NfcTarget(NfcDevice):
    def __init__(self, devdesc, targettype=None, *args, **kwargs):
        NfcDevice.__init__(self, devdesc, *args, **kwargs)
        ret = self.init(targettype)
        # print "NfcTarget.init: ", ret

    def init(self, *args, **kwargs):
        self.target_init(*args, **kwargs)

    def receive_bits(self, *args, **kwargs):
        return self.target_receive_bits(*args, **kwargs)

    def receive_bytes(self, *args, **kwargs):
        return self.target_receive_bytes(*args, **kwargs)

    def send_bits(self, *args, **kwargs):
        return self.target_send_bits(*args, **kwargs)

    def send_bytes(self, *args, **kwargs):
        return self.target_send_bytes(*args, **kwargs)


class NfcInitiator(NfcDevice):
    def __init__(self, *args, **kwargs):
        NfcDevice.__init__(self, *args, **kwargs)
        self.init()

    def init(self, *args, **kwargs):
        return self.initiator_init(*args, **kwargs)

    def select_passive_target(self, *args, **kwargs):
        return self.initiator_select_passive_target(*args, **kwargs)

    def list_passive_targets(self, *args, **kwargs):
        return self.initiator_list_passive_targets(*args, **kwargs)

    def deselect_target(self, *args, **kwargs):
        return self.initiator_deselect_target(*args, **kwargs)

    def select_dep_target(self, *args, **kwargs):
        return self.initiator_select_dep_target(*args, **kwargs)

    def poll_targets(self, *args, **kwargs):
        return self.initiator_poll_targets(*args, **kwargs)

    def transceive_bits(self, *args, **kwargs):
        return self.initiator_transceive_bits(*args, **kwargs)

    def transceive_bytes(self, *args, **kwargs):
        return self.initiator_transceive_bytes(*args, **kwargs)


if __name__ == '__main__':
    # print get_version()
    devs_list = list_devices(True)
    # dev = NfcDevice(devs_list[0])
    # devs = list_devices()
    # dev = devs[0].connect()
    # dev.initiator_init()
    # dev.initiator_select_passive_target(dev.NMT_ISO14443A, dev.NBR_UNDEFINED, "")
