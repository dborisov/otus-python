#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';

from datetime import datetime as dt
import os
import argparse
import configparser
import logging
import sys
import re
import gzip
import collections
import json
import statistics

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "REPORT_TPL": "./report.html",
    "LOG_DIR": "./log",
    "LOG_NAME": "nginx-access-ui.log"
}


class LevelFilter(object):
    def __init__(self, level):
        self.level = level

    def filter(self, record):
        return record.levelno != self.level


def get_latest_file(file_name, file_list):

    pattern = r'^%s-(?P<date>\d{8})(?:$|\.(?P<ext>gz))$' % file_name
    matches = [re.match(pattern, f) for f in file_list]
    tuples = [match.groupdict() for match in matches if match]
    latest = max(tuples, key=lambda x: dt.strptime(x['date'], '%Y%m%d'))

    date = latest['date']
    ext = latest['ext']
    if ext:
        file = '%s-%s.%s' % (file_name, date, ext)
    else:
        file = '%s-%s' % (file_name, date)

    return {'file': file, 'date': dt.strptime(date, '%Y%m%d'), 'ext': ext}


def xreadlines(path):

    if path.endswith(".gz"):
        f = gzip.open(path)
    else:
        f = open(path)

    for line in f:
        yield line.decode('utf-8')

    f.close()


def process_log_file(path):
    r = re.compile(
        r"(?P<remote_addr>[\d\.]+)\s"
        r"(?P<remote_user>\S*)\s+"
        r"(?P<http_x_real_ip>\S*)\s"
        r"\[(?P<time_local>.*?)\]\s"
        r'"(?P<request>.*?)"\s'
        r"(?P<status>\d+)\s"
        r"(?P<body_bytes_sent>\S*)\s"
        r'"(?P<http_referer>.*?)"\s'
        r'"(?P<http_user_agent>.*?)"\s'
        r'"(?P<http_x_forwarded_for>.*?)"\s'
        r'"(?P<http_x_request_id>.*?)"\s'
        r'"(?P<http_x_rb_user>.*?)"\s'
        r"(?P<request_time>\d+\.\d+)\s*"
    )
    lines = xreadlines(path)
    return (r.match(line).groupdict() for line in lines)


def build_report(lines):
    req_times = collections.defaultdict(list)
    for line in lines:
        req_times[line['request'].split()[1]].append(
            float(line['request_time']))

    total_count = total_time = 0
    for v in req_times.values():
        total_count += len(v)
        total_time += sum(v)

    stat = []
    for request, times in req_times.items():
        times.sort()
        stat.append({
            'url': request,
            'count': len(times),
            'count_perc': round(100 * len(times) / float(total_count), 3),
            'time_avg': round(sum(times) / len(req_times), 3),
            'time_max': round(max(times), 3),
            'time_med': round(statistics.median(times), 3),
            'time_sum': round(sum(times), 3),
            'time_perc': round(100 * sum(times) / total_time, 3),
        })
    return stat


def write_report(report, template_file, report_file):
    with open(template_file) as f:
        html = f.read()

    html = html.replace('$table_json', json.dumps(report))

    with open(report_file, "w") as f:
        f.write(html)


def main(config):

    try:
        # Args parsing
        arg_parser = argparse.ArgumentParser()
        arg_parser.add_argument(
            '-c',
            '--config',
            metavar='PATH',
            help='path to config file',
            default="./config.ini"
        )
        args = arg_parser.parse_args()

        # Config parsing
        try:
            conf_parser = configparser.ConfigParser(config)
            conf_parser.read_file(open(args.config))
            config = conf_parser.defaults()
        except Exception as e:
            sys.exit("Can't parse config: %s" % e)

        # Logging configuration
        try:
            logging.basicConfig(
                filename=config.get('log_file', None),
                level=logging.NOTSET,
                format='[%(asctime)s] %(levelname).1s %(message)s',
                datefmt='%Y.%m.%d %H:%M:%S'
            )

            logger = logging.getLogger()
            logger.addFilter(LevelFilter(logging.WARNING))
            logger.addFilter(LevelFilter(logging.DEBUG))
            logger.addFilter(LevelFilter(logging.CRITICAL))
        except Exception as e:
            sys.exit("Can't configure logging: %s" % e)

        latest_log = get_latest_file(
            config['log_name'],
            os.listdir(config['log_dir'])
        )
        report_file = "%s/%s-%s.html" % (
            config['report_dir'],
            config['log_name'],
            latest_log['date'].strftime("%Y-%m-%d")
        )
        log_file = "%s/%s" % (config['log_dir'], latest_log['file'])

        if os.path.isfile(report_file):
            sys.exit(0)

        processed_log = process_log_file(log_file)
        report = build_report(processed_log)
        write_report(report, config['report_tpl'], report_file)

    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        logging.exception(e)
        sys.exit(1)


if __name__ == "__main__":
    main(config)
