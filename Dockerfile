FROM python:3.7

RUN mkdir /src
COPY . /src
WORKDIR /src
RUN python setup.py build && python setup.py install
RUN rm -rf /src
ENTRYPOINT [ "djangohunter" ]