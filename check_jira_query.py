#!/usr/bin/python
# -*- coding: utf8 -*-

# "THE BEER-WARE LICENSE" - - - - - - - - - - - - - - - - -
# This file was initially written by Philip Eklöf.
# As long as you retain this notice you can do whatever you
# want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return.
# - - - - - - - - - - - - - - - - - - - - - <poe@epux.se> -

import argparse
import json
import logging
import nagiosplugin
import requests
import sys

class JIRA_REST_API(nagiosplugin.Resource):
	def __init__(self, url, username=None, password=None):
		self.url = url  + '/rest/api/2'
		if username and password:
				self.auth = (username, password)
		else:
				self.auth = None

	def query(self, type, path, payload):
		try:
			if type == 'get':
				r = requests.get(
					self.url + path,
					headers={
							'Accept-Encoding': 'text/plain',
							'User-Agent': 'check_jira_query'
						},
					auth=self.auth,
					params=payload
					)

			elif type == 'post':
				r = requests.post(
					self.url + path,
					headers={
							'Accept-Encoding': 'text/plain',
							'Content-Type': 'application/json',
							'User-Agent': 'check_jira_query'
						},
					auth=self.auth,
					data=json.dumps(payload)
					)

		except requests.ConnectionError as e:
			raise nagiosplugin.CheckError('Connection error: %s' % e)
		except requests.HTTPError as e:
			raise nagiosplugin.CheckError('HTTP error: %s' % e)
		except:
			raise nagiosplugin.CheckError('Unhandled HTTP error: %s' \
				% sys.exc_info()[1])

		_log.info('\n-*- Request/Respone information:')
		_log.info(' URL: %s' % r.url)
		_log.info('Code: %s' % r.status_code)
		_log.info('Data:\n%s\n' % r.text)

		try:
			dec_fail = False
			dec = json.loads(r.text)
		except ValueError:
			dec_fail = True
		else:
			_log.debug('\n-*- Respone contained valid JSON:')
			_log.debug(json.dumps(dec, indent=2))

		if r.status_code != 200:
			raise nagiosplugin.CheckError(
				'Server could not fulfill the request (code: %s)' % \
				r.status_code
				)

		if dec_fail:
			raise nagiosplugin.CheckError('Invalid JSON data.')

		return dec

	def query_search(self, jql):
		return self.query('post', '/search', {'fields': ['key'], 'jql': jql})

class JIRAQuery(nagiosplugin.Resource):
	def __init__(self, opts):
		self.opts = opts

	def probe(self):
		jira = JIRA_REST_API(
			self.opts.url, self.opts.username, self.opts.password)
		data = jira.query_search(self.opts.jira_query)

		if not 'issues' in data:
			raise nagiosplugin.CheckErrors('No issues in result data.')

		for issue in data['issues']:
			yield nagiosplugin.Metric('key', issue['key'])

		yield nagiosplugin.Metric(
				self.opts.label,
				data['total'],
				min=0,
				)

class JIRASummary(nagiosplugin.Summary):
	def __init__(self, label):
			self.label = label

	def ok(self, results):
		return results[self.label].metric.contextobj.describe(
			results[self.label].metric)

	def verbose(self, results):
		ret = ''
		for res in results:
			if not res.metric:
				continue
			if res.metric.name != 'key':
				continue
			ret += res.metric.contextobj.describe(res.metric) + '\n'
		return ret

def arg_parse():
	parser = argparse.ArgumentParser()

	parser.add_argument("-j", "--jira-query", required=True,
		help="JQL search string.")

	parser.add_argument("-U", "--url", required=True,
		help="JIRA server URL (^https?://.+/rest$).")

	parser.add_argument("-u", "--username",
		help="REST API username.")

	parser.add_argument("-p", "--password",
		help="REST API password.")

	parser.add_argument("-s", "--status-output",
		default="Total count: {value}",
		help="""Custom status output text. The {value} placeholder is used to
			include the resulting total of the query, e.g.
			-s 'Currently {value} open issues'""")

	parser.add_argument("-e", "--extra-output",
		help="""Custom long output text. Like -s, but this will be output per
			every issue found, if running in verbose mode. In this case,
			{value} contains the JIRA issue key. Defaults to the issue URL.""")

	parser.add_argument("-l", "--label", default="count",
		help="Custom performance data label (default: count).")

	parser.add_argument("-w", "--warning",
		help="Warning threshold. Supports Nagios ranges.")

	parser.add_argument("-c", "--critical",
		help="Critical threshold. Supports Nagios ranges.")

	parser.add_argument("-t", "--timeout", type=int, default=10,
		help="Plugin execution timeout, in seconds (default: 10).")

	parser.add_argument("-v", "--verbose", action="count", default=0,
		help="Increase the verbosity level.")

	return parser.parse_args()

@nagiosplugin.guarded
def main():
	# Parse and verify arguments.
	opts = arg_parse()

	# Set up the main metric context.
	try:
		nagios_count_scalar = nagiosplugin.ScalarContext(
			opts.label, opts.warning, opts.critical,
			fmt_metric=opts.status_output
			)
	except ValueError as e:
		raise nagiosplugin.CheckError("Invalid threshold values: %s" % e)

	# Set up context used to output verbose data for found issue keys.
	nagios_key_context = nagiosplugin.Context('key')
	if opts.extra_output:
		nagios_key_context.fmt_metric=opts.extra_output
	else:
		nagios_key_context.fmt_metric='{value}: ' + opts.url + '/browse/{value}'


	c = nagiosplugin.Check(
		nagios_count_scalar,
		nagios_key_context,
		JIRAQuery(opts),
		JIRASummary(opts.label)
		)

	# The output prefix, which could be set to None with nagiosplugin 1.2.2.
	c.name = 'JIRA Query'

	# Gogogo.
	c.main(verbose=opts.verbose, timeout=opts.timeout)


# Set up log environment.
_log = logging.getLogger('nagiosplugin')

if __name__ == '__main__':
	main()
