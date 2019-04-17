FROM python:2

# Environment variables
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -qq -y git python-pycurl python2.7-dev libcurl4-gnutls-dev librtmp-dev gcc && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
ADD . /project/
WORKDIR /project
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

ENTRYPOINT ["python"]
CMD ["app.py"]