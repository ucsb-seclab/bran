FROM ubuntu

RUN apt-get -y update

RUN apt-get install -y --no-install-recommends apt-utils

RUN apt-get -y install sl htop psmisc zip psutils time iotop iputils-ping net-tools build-essential ssh sshfs bash-completion rsync \
                       git screen stress tmux iperf libxml2-dev openjdk-8-jre openjdk-8-jdk ipython pypy python-dev python-pip virtualenvwrapper \
                       libxml2-dev pkg-config curl cmake sudo vim bc pmccabe indent zip unzip git
 
RUN pip install requests flask bs4 python-dateutil

RUN bash -c "echo \"nameserver 8.8.8.8\" >> /etc/resolv.conf"

RUN mkdir /repos

RUN git clone https://github.com/torvalds/linux.git /repos/kernelmain

ADD data /data

ENV PATH=/data/bin:$PATH

CMD bash -c "cd /data/scripts; python vul_func_extra_client.py http://192.168.61.173:8080"

