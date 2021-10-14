import errno
import optparse
import os
from apdu_parser import *


def main():
    command_descriptions = parse_description_file("command_descriptions.txt")
    response_descriptions = parse_description_file("response_descriptions.txt")
    # print command_descriptions
    apdu_line = "00 a4 04 00 07 a0 00 00  00 03 10 10 00"
    desc, cla, ins, p1, p2, lc, le, data = parse_apdu_command(apdu_line, command_descriptions)
    show_apdu_command(desc, cla, ins, p1, p2, lc, le, data, None)
    last_apdu_command = apdu_line
    apdu_line = "6f 2b 84 07 a0 00 00 00  03 10 10 a5 20 50 04 56 49 53 41 9f 38 0c 9f 66  04 9f 02 06 9f 37 04 5f 2a 02 bf 0c 08 9f 5a 05  60 06 43 06 43 90 00"
    desc, category, sw1, sw2, data = parse_apdu_response(apdu_line, response_descriptions, last_apdu_command)
    show_apdu_response(desc, category, sw1, sw2, data, None)

    pass


if __name__ == '__main__':
    main()
