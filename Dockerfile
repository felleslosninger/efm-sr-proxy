FROM openjdk:8-jre-slim

EXPOSE 8080

ENV JAVA_OPTS="" \
    APP_DIR=/var/lib/digdir/ \
    APP_FILE_NAME=app.jar

RUN addgroup --system --gid 1001 spring && adduser --system --uid 1001 --group spring
# RUN chown -R spring:spring /opt
# RUN mkdir /logs && chown -R spring:spring /logs

ARG jarPath
ADD --chown=spring:spring ${jarPath} ${APP_DIR}$APP_FILE_NAME

RUN chmod -R +x $APP_DIR
USER spring
ENTRYPOINT ["sh", "-c", "java ${JAVA_OPTS} -jar ${APP_DIR}$APP_FILE_NAME ${0} ${@}"]

HEALTHCHECK --interval=30s --timeout=2s --retries=3 \
CMD wget --no-verbose --tries=1 --spider "http://localhost:8080/actuator/health" || exit 1