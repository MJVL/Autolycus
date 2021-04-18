FROM python:3.6.7

LABEL maintainer="michaeljvanleeuwen@gmail.com"

RUN apt-get update -y

# get past input prompts
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y tshark

COPY src src

COPY setup.py .

# copied over for setuptools
COPY README.md .

RUN python3 setup.py install

CMD ["autolycus", "-h"]