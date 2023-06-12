FROM redpwn/jail:sha-a795cdd

COPY --from=ubuntu@sha256:703218c0465075f4425e58fac086e09e1de5c340b12976ab9eb8ad26615c3715 / /srv

COPY bin/horse /srv/app/run
COPY bin/flag.txt /srv/app/flag.txt
RUN mv /srv/app/flag.txt /srv/app/flag-`cat /proc/sys/kernel/random/uuid`.txt
