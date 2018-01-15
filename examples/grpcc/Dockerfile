FROM node:8.9.4-alpine

RUN apk add --update --no-cache python

# `yarn global add` is easier than `npm install -g` in this case due to the npm bug:
#   https://github.com/nodejs/docker-node/issues/423#issuecomment-306470507
# To work-around the npm bug, we need to upgrade it like this:
# https://github.com/me-ventures/angular-cli-docker/commit/3d40e583e865817831e93c55fab01cb6857a24c7
# However, isn't it too much boiler-plate just for installing a single module? :)

# RUN yarn global add grpcc

# see https://github.com/njpatel/grpcc/pull/48
RUN yarn global add https://github.com/njpatel/grpcc/archive/d82c570.tar.gz

ADD https://raw.githubusercontent.com/njpatel/grpcc/master/test/test.proto /test.proto

RUN apk add --update --no-cache nghttp2

ENTRYPOINT ["grpcc"]
