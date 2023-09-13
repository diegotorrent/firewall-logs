# by DFT - To use with Arris routers.
import requests
import pandas as pd
from datetime import datetime
from time import sleep, time, localtime, strftime

sleep_save = 15  # Time in seconds used to auto save data

sleep_update = 1  # Time in seconds used to update the firewall log

log_file = "myfw-01.txt"

line_separator = "\t"  # Character separator for the log file

firewall_logs = []

cols = ["dthr", "type", "dst_port", "src_ip", ]  # Select columns to print

# Cookies
cook = {
    "credential": ""
}
# URI Resource
url = "http://192.168.0.1/walk?oids=1.3.6.1.4.1.4115.1.20.1.1.5.19.1.1;&_n=67238077&_=19694563325654"

# Pandas tweak
pd.set_option('display.max_columns', None)
pd.set_option('display.expand_frame_repr', False)


def save_log():
    try:
        global firewall_logs, log_file, line_separator

        with open(log_file, "a") as fp:
            for i, log in enumerate(firewall_logs):
                fp.write(
                    "\n" + log["dthr"] + line_separator +
                    log["type"] + line_separator +
                    log["dst_ip"] + line_separator +
                    log["dst_port"] + line_separator +
                    log["src_ip"] + line_separator +
                    log["src_port"] + line_separator +
                    log["direction"] + line_separator)

    except Exception as e:
        print("save_log() Exception", e)


def update_log():
    global firewall_logs
    try:
        firewall_logs_old = [r["direction"] for r in firewall_logs]
        r = requests.get(url, cookies=cook)
        for i, row in enumerate(r.content.split(b"\n")):
            inf = str(row).split('"')
            fw_row = inf[len(inf) - 2] if len(inf) - 2 > 0 and inf[len(inf) - 2][:1] not in ("$", "F") else ""
            if len(fw_row):
                aux = fw_row.split(" - ")

                if len(aux) > 1:

                    fw_row_type = aux[0]

                    fw_row_direction = aux[1]

                    if fw_row_direction not in firewall_logs_old:

                        # Saving time with precision
                        dthr_log = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

                        # Direction
                        fw_row_dir = fw_row_direction.split(" ")
                        fw_row_source = fw_row_dir[0]
                        fw_row_dest = fw_row_dir[1] if len(fw_row_dir) > 1 else "-"

                        # Type
                        fw_row_type = fw_row_type.replace(":", "").replace("[", "").split("]")
                        fw_row_type = fw_row_type[1] + "/" + fw_row_type[0] if len(fw_row_type) > 1 else fw_row_type
                        fw_row_type = fw_row_type.replace("TCP Packet/","").replace("UDP Packet/","").replace("ICMP Packet/","")
                        # Source
                        source_port = fw_row_source.replace("Source:", "").split(",")
                        source_ip = source_port[0]
                        source_port = source_port[1]

                        # Destination
                        dst_port = fw_row_dest.replace("Destination:", "").split(",")
                        dst_ip = dst_port[0]
                        dst_port = dst_port[1] if len(dst_port) > 1 else dst_port[0]

                        # Appeding
                        firewall_logs.append({
                            "dthr": dthr_log,
                            "src_ip": source_ip,
                            "src_port": source_port,
                            "dst_ip": dst_ip,
                            "dst_port": dst_port,
                            "type": fw_row_type,
                            "direction": fw_row_direction,
                        })
                else:
                    print("ERROR")

    except Exception as e:
        print("update() Exception", e)


# Main
print("\033[2H\033[2J" + "*" * 60, "\nBegin time: ", strftime('%Y-%m-%d %H:%M:%S', localtime(time())))

last_save = time()

while True:

    update_log()

    if len(firewall_logs):

        dthr = time()

        df = pd.DataFrame(firewall_logs)

        df = df[cols]

        print("\033[2H\033[2J" + "*" * 60, "\nLast update: ", strftime('%Y-%m-%d %H:%M:%S', localtime(dthr)))

        print(df.sort_values(by="dthr"))

        if dthr > last_save + sleep_save:

            save_log()

            last_save = time()

            print("*" * 60, "\nThe log file was updated. ", strftime('%Y-%m-%d %H:%M:%S', localtime(last_save)))

    sleep(sleep_update)
