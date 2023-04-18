import requests
import argparse
import apiCall
from exception import APIError
from time import sleep

class slack_bot():

    parser = argparse.ArgumentParser(description="Obtaining for scanning and obtaining information from potentially malicious websites using by CriminalIP and urlScan")
    parser.add_argument("--k", "--key", type=str, help="CriminalIP API Key")
    parser.add_argument("--o", "--offset", type=int, help="Starting position in the dataset(entering in increments of 10", default=0)
    parser.add_argument("--c", "--channel", type=str, help="Input my slack channel")
    parser.add_argument("--s", "--query", type=str, help="Input data for Searching")
    parser.add_argument("--t", "--token", type=str, help="Input slack bot token")
    args = parser.parse_args()

    def post_message(self, token, channel, message):
        response = requests.post("https://slack.com/api/chat.postMessage",
                                headers={"Authorization" : "Bearer " + token},
                                data={"channel" : channel, "text" : message}
                                )
        print(response)

    def main(self):
        
        print("     _               _             _____ ______                                  _         ") 
        print("    | |             | |           |_   _|| ___ \                                | |        ")
        print("___ | |  __ _   ___ | | __ ______   | |  | |_/ / _ __   ___  _ __    ___   _ __ | |_       ")
        print("/ __|| | / _` | / __|| |/ /|______|  | |  |  __/ | '__| / _ \| '_ \  / _ \ | '__|| __|     ")
        print("\__ \| || (_| || (__ |   <          _| |_ | |    | |   |  __/| |_) || (_) || |   | |_      ")
        print("|___/|_| \__,_| \___||_|\_\         \___/ \_|    |_|    \___|| .__/  \___/ |_|    \__|     ")
        print("                                                           | |                             ")
        print("                                                            |_|                            ")

        try:
            Criminal_API_KEY = self.args.k
            query = self.args.s
            offset = self.args.o
            channel = self.args.c
            token = self.args.t

            report_result_list = []
            real_ip_list = []
            real_ip_list_result = {}
            message = "*Connected_ip with Domain* \r\n"

            api = apiCall.CriminalIP(Criminal_API_KEY)
            scan_result = api.criminal_domain_scan(query)
            scan_id = scan_result['data']['scan_id']
            print('scan_id: ', end='')
            print(scan_id)

        # Find ip's domain $ subdomain by searching domain scan api
            if scan_id != '':
                sleep(5)
                i = 1
                try:
                    while(True):
                        report_result = api.criminal_domain_report(scan_id)
                        if i < 50:
                            ++i
                            if 'No Search Data' in report_result['message']:
                                continue
                            else:
                                report_result_list = report_result['data']['connected_ip_info']
                                for value in report_result_list:
                                    real_ip = value['ip']
                                    real_ip_list.append(real_ip)
                                break
                        break
                except Exception as e:
                    print(e)

            # ip's safe-dns-server check
            for value in real_ip_list:
                safe_dns_result = api.criminal_is_safe_dns_server(value)

                if safe_dns_result['is_safe_dns_server']:
                    real_ip_list_result[value] = ' *Safe* '
                else:
                    real_ip_list_result[value] = ' *Not Safe* '

            for key, value in real_ip_list_result.items():
                message += str(key) + ":" + str(value) + "\r\n"
            message = "*Search Query Result*: " + query + "\r\n" + message

            for value in report_result_list:
                message += str(value) + "\r\n"

            self.post_message(token, channel, message)
        except Exception as e:
            print(e)

if __name__ == '__main__':
    main_service = slack_bot()
    main_service.main()
