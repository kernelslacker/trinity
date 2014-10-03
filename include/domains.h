#pragma once

extern const char * get_domain_name(unsigned int domain);
extern void find_specific_domain(const char *domainarg);
extern void parse_exclude_domains(const char *arg);
extern unsigned int find_next_enabled_domain(unsigned int from);
