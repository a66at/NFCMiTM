import errno
import optparse
import os


# Output colors
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
LIGHT_PURPLE = '\033[94m'
PURPLE = '\033[95m'
BLUE = '\033[96m'
ENDC = '\033[0m'


def parse_description_file(filename):
    try:
        f = open(filename, "r")
    except:
        print "[*] Error while opening file: {}".format(filename)

    lines = f.readlines()
    results = []
    try:
        for line in lines:
            results.append(line.strip().split("\t"))
    except:
        print "[*] Error while parsing descriptions file: {}".format(filename)

    f.close()
    return results


def parse_apdu_command(line, command_descriptions):
    command_bytes = line.upper().strip().split(" ")
    command_bytes_len = len(command_bytes)
    desc = "(NOT FOUND)"

    # Header: CLA | INS | P1 | P2
    cla = command_bytes[0]
    ins = command_bytes[1]
    p1 = command_bytes[2]
    p2 = command_bytes[3]

    # Body: [ LC | DATA ] | [ LE ]
    lc = None
    le = None
    data = None

    if command_bytes_len == 5:  # LE
        le = command_bytes[4]
    elif command_bytes_len > 5:
        lc = command_bytes[4]
        lc_int = int("0x" + lc, 0)
        if command_bytes_len > 5 + lc_int:  # LC | DATA | LE
            le = command_bytes[5+lc_int]
            data = command_bytes[5:-1]
        else:  # LC | DATA
            data = command_bytes[5:]

    # Parse CLA (TO-DO)

    # Parse IN
    for cd in command_descriptions:
        if ins == cd[2]:  # INS
            desc = "{} ({})".format(cd[0], cd[1])  # INS NAME (INS DESC)
            break

    # Parse P1, P2 (TO-DO)

    # Parse DATA (TO-DO)

    return desc,cla,ins,p1,p2,lc,le,data


def parse_apdu_response(line, response_descriptions, last_apdu_command=None):
    response_bytes = line.upper().strip().split(" ")
    desc = "(NOT FOUND)"
    category = None

    # Data field: DATA (optional)
    data = None
    response_bytes_len = len(response_bytes)
    if response_bytes_len > 2:
        data = response_bytes[2:]

    # Trailer: SW1 | SW2
    sw1 = response_bytes[-2]
    sw2 = response_bytes[-1]

    # Parse SW1 SW2 codes
    for rd in response_descriptions:
        if sw1 == rd[0] and sw2 == rd[1]:  # SW1, SW2
            desc = "{} [{}]".format(rd[3], rd[2])
            category = rd[2]
            break

    return desc, category, sw1, sw2, data
    # TO-DO:
    #   - RECOGNIZE SWs THAT INCLUDE XX VALUES
    #   - PARSE CUSTOM RESPONSE CODES DEPENDING ON LAST APDU COMMAND


def show_apdu_command(desc, cla, ins, p1, p2, lc, le, data, colors):
    print "{} : {}".format(ins, desc)  # INS : INS_NAME (INS_DESC)

    if colors:
        cla = RED + cla + ENDC
        #ins = GREEN + ins + ENDC
        p1 = LIGHT_PURPLE + p1 + ENDC
        p2 = LIGHT_PURPLE + p2 + ENDC
        if lc is not None:
            lc = GREEN + lc + ENDC
        if le is not None:
            le = BLUE + le + ENDC

    line = "\t" + cla + " " + ins + " " + p1 + " " + p2
    if lc is not None:
        line += " " + str(lc)

    if data is not None:
        line += " " + (" ").join(data)

    if le is not None:
        line += " " + le

    print line + "\n"


def show_apdu_response(desc, category, sw1, sw2, data, colors):
    print "{} {} : {}".format(sw1, sw2, desc)  # SW1 SW2 : DESC

    if colors:
        if category == "E":  # Error
            sw1 = RED + sw1 + ENDC
            sw2 = RED + sw2 + ENDC

        if category == "W":  # Warning
            sw1 = YELLOW + sw1 + ENDC
            sw2 = YELLOW + sw2 + ENDC

        if category == "I":  # Info
            sw1 = GREEN + sw1 + ENDC
            sw2 = GREEN + sw2 + ENDC

        if category == "S":  # Security
            sw1 = BLUE + sw1 + ENDC
            sw2 = BLUE + sw2 + ENDC

    line = "\t"
    if data is not None:
        line += " ".join(data) + " "

    print line + sw1 + " " + sw2 + "\n"


def main():
    parser = optparse.OptionParser('usage %prog -i <input_file>')
    parser.add_option('-i', '--input', dest='input_file', type='string', help='specify input file')
    parser.add_option('-o', '--output', dest='output_file', type='string', help='specify output file')

    parser.add_option('-c', '--commands', action='store_true', dest='commands_only', default=False, help='specify if input file contains only APDU commands')
    parser.add_option('-r', '--responses', action='store_true', dest='responses_only', default=False, help='specify if input file contains only APDU responses')

    parser.add_option('-C', '--command-descriptions', dest='command_descriptions', type='string', help='specify custom command descriptions file')
    parser.add_option('-R', '--response-descriptions', dest='response_descriptions', type='string', help='specify custom response descriptions file')

    parser.add_option('-T', '--colors', action='store_true', dest='colors', default=False, help='show terminal output in different colors')

    (options, args) = parser.parse_args()

    input_file = None
    output_file = None
    last_apdu_command = None

    commands_only = options.commands_only
    responses_only = options.responses_only

    command_descriptions = None
    response_descriptions = None

    colors = options.colors

    # Input file
    if options.input_file is None:
        print parser.usage
        print
        exit(0)
    else:
        input_file = open(options.input_file, "r")
        apdu_lines = input_file.readlines()
        input_file.close()

    # Output file
    if options.output_file is not None:
        if not os.path.exists(os.path.dirname(options.output_file)):
            try:
                os.makedirs(os.path.dirname(options.output_file))
            except OSError as e:  # Guard against race condition
                if e.errno != errno.EEXIST:
                    raise

        output_file = open(options.output_file, "w")

    if commands_only and options.responses_only:
        print parser.usage
        print "[*] Error: --commands and --responses options cannot be set at the same time"
        exit(0)

    # Custom command descriptions
    if not responses_only:
        if options.command_descriptions is not None:
            command_descriptions = parse_description_file(options.command_descriptions)
        else:
            command_descriptions = parse_description_file("command_descriptions.txt")

    # Custom response descriptions
    if not commands_only:
        if options.response_descriptions is not None:
            response_descriptions = parse_description_file(options.response_descriptions)
        else:
            response_descriptions = parse_description_file("response_descriptions.txt")

    # Parse APDU lines
    is_next_command = not responses_only

    for apdu_line in apdu_lines:
        apdu_line = apdu_line.strip()
        # APDU command
        if is_next_command:
            desc,cla,ins,p1,p2,lc,le,data = parse_apdu_command(apdu_line, command_descriptions)
            last_apdu_command = apdu_line
            is_next_command = commands_only
            # Show parsed results
            show_apdu_command(desc, cla, ins, p1, p2, lc, le, data, colors)
            # Write output to output file
            if output_file is not None:
                output_file.write(ins + " : " + desc + ")\n")  # INS : INS_NAME (INS_DESC)
                output_file.write("\t" + apdu_line + "\n")
        # APDU response
        else:
            desc, category, sw1, sw2, data = parse_apdu_response(apdu_line, response_descriptions, last_apdu_command)
            is_next_command = not responses_only
            # Show parsed results
            show_apdu_response(desc, category, sw1, sw2, data, colors)
            # Write output to output file
            if output_file is not None:
                output_file.write(sw1 + "" + sw2 + " : " + desc + "\n")  # SW1SW2 : CODE_DESC
                output_file.write("\t" + apdu_line + "\n")

    # Close output files
    if output_file is not None:
        output_file.close()


if __name__ == '__main__':
    main()
