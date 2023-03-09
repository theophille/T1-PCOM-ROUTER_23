FROM jokeswar/base-ctl

RUN echo "Hello from Docker"

RUN apt update
RUN DEBIAN_FRONTEND=nonintearctive apt install -qy git
RUN DEBIAN_FRONTEND=nonintearctive apt install -qy mininet
RUN DEBIAN_FRONTEND=nonintearctive apt install -qy openvswitch-testcontroller
RUN DEBIAN_FRONTEND=nonintearctive apt install -qy python3-pip
RUN DEBIAN_FRONTEND=nonintearctive cp /usr/bin/ovs-testcontroller /usr/bin/ovs-controller
RUN DEBIAN_FRONTEND=nonintearctive pip3 install scapy
RUN DEBIAN_FRONTEND=nonintearctive pip3 install pathlib
RUN DEBIAN_FRONTEND=nonintearctive pip3 install git+https://github.com/mininet/mininet.git

COPY ./checker ${CHECKER_DATA_DIRECTORY}
