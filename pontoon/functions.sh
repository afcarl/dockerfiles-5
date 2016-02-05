#!/bin/bash
set -e
source ${GITLAB_RUNTIME_DIR}/env-defaults

SYSCONF_TEMPLATES_DIR="${GITLAB_RUNTIME_DIR}/config"
USERCONF_TEMPLATES_DIR="${GITLAB_DATA_DIR}/config"

GITLAB_CONFIG="${GITLAB_INSTALL_DIR}/config/gitlab.yml"
GITLAB_DATABASE_CONFIG="${GITLAB_INSTALL_DIR}/config/database.yml"
GITLAB_UNICORN_CONFIG="${GITLAB_INSTALL_DIR}/config/unicorn.rb"
GITLAB_RACK_ATTACK_CONFIG="${GITLAB_INSTALL_DIR}/config/initializers/rack_attack.rb"
GITLAB_SMTP_CONFIG="${GITLAB_INSTALL_DIR}/config/initializers/smtp_settings.rb"
GITLAB_RESQUE_CONFIG="${GITLAB_INSTALL_DIR}/config/resque.yml"
GITLAB_SECRETS_CONFIG="${GITLAB_INSTALL_DIR}/config/secrets.yml"
GITLAB_ROBOTS_CONFIG="${GITLAB_INSTALL_DIR}/public/robots.txt"
GITLAB_SHELL_CONFIG="${GITLAB_SHELL_INSTALL_DIR}/config.yml"
GITLAB_NGINX_CONFIG="/etc/nginx/sites-enabled/gitlab"
GITLAB_CI_NGINX_CONFIG="/etc/nginx/sites-enabled/gitlab_ci"

# Compares two version strings `a` and `b`
# Returns
#   - negative integer, if `a` is less than `b`
#   - 0, if `a` and `b` are equal
#   - non-negative integer, if `a` is greater than `b`
vercmp() {
  expr '(' "$1" : '\([^.]*\)' ')' '-' '(' "$2" : '\([^.]*\)' ')' '|' \
       '(' "$1.0" : '[^.]*[.]\([^.]*\)' ')' '-' '(' "$2.0" : '[^.]*[.]\([^.]*\)' ')' '|' \
       '(' "$1.0.0" : '[^.]*[.][^.]*[.]\([^.]*\)' ')' '-' '(' "$2.0.0" : '[^.]*[.][^.]*[.]\([^.]*\)' ')' '|' \
       '(' "$1.0.0.0" : '[^.]*[.][^.]*[.][^.]*[.]\([^.]*\)' ')' '-' '(' "$2.0.0.0" : '[^.]*[.][^.]*[.][^.]*[.]\([^.]*\)' ')'
}

## Execute a command as GITLAB_USER
exec_as_git() {
  if [[ $(whoami) == ${GITLAB_USER} ]]; then
    $@
  else
    sudo -HEu ${GITLAB_USER} "$@"
  fi
}

## Copies configuration template to the destination as the specified USER
### Looks up for overrides in ${USERCONF_TEMPLATES_DIR} before using the defaults from ${SYSCONF_TEMPLATES_DIR}
# $1: copy-as user
# $2: source file
# $3: destination location
# $4: mode of destination
install_template() {
  local OWNERSHIP=${1}
  local SRC=${2}
  local DEST=${3}
  local MODE=${4:-0644}
  if [[ -f ${USERCONF_TEMPLATES_DIR}/${SRC} ]]; then
    cp ${USERCONF_TEMPLATES_DIR}/${SRC} ${DEST}
  elif [[ -f ${SYSCONF_TEMPLATES_DIR}/${SRC} ]]; then
    cp ${SYSCONF_TEMPLATES_DIR}/${SRC} ${DEST}
  fi
  chmod ${MODE} ${DEST}
  chown ${OWNERSHIP} ${DEST}
}

## Replace placeholders with values
# $1: file with placeholders to replace
# $x: placeholders to replace
update_template() {
  local FILE=${1?missing argument}
  shift

  [[ ! -f ${FILE} ]] && return 1

  local VARIABLES=($@)
  local USR=$(stat -c %U ${FILE})
  local tmp_file=$(mktemp)
  cp -a "${FILE}" ${tmp_file}

  local variable
  for variable in ${VARIABLES[@]}; do
    # Keep the compatibilty: {{VAR}} => ${VAR}
    sed -ri "s/[{]{2}$variable[}]{2}/\${$variable}/g" ${tmp_file}
  done

  # Replace placeholders
  (
    export ${VARIABLES[@]}
    local IFS=":"; sudo -HEu ${USR} envsubst "${VARIABLES[*]/#/$}" < ${tmp_file} > ${FILE}
  )
  rm -f ${tmp_file}
}
pontoon_check_database_connection() {
  prog=$(find /usr/lib/postgresql/ -name pg_isready)
  prog="${prog} -h ${DB_HOST} -p ${DB_PORT} -U ${DB_USER} -d ${DB_NAME} -t 1"
  timeout=60
  while ! ${prog} >/dev/null 2>&1
  do
    timeout=$(expr $timeout - 1)
    if [[ $timeout -eq 0 ]]; then
      echo
      echo "Could not connect to database server. Aborting..."
      return 1
    fi
    echo -n "."
    sleep 1
  done
  echo
}

pontoon_finalize_database_parameters() {
  # is a postgresql database linked?
  # requires that the postgresql containers have exposed
  # port 5432 .
  if [[ -n ${POSTGRESQL_PORT_5432_TCP_ADDR} ]]; then
    DB_ADAPTER=${DB_ADAPTER:-postgresql}
    DB_HOST=${DB_HOST:-${POSTGRESQL_PORT_5432_TCP_ADDR}}
    DB_PORT=${DB_PORT:-${POSTGRESQL_PORT_5432_TCP_PORT}}

    # support for linked official postgres image
    DB_USER=${DB_USER:-${POSTGRESQL_ENV_POSTGRES_USER}}
    DB_PASS=${DB_PASS:-${POSTGRESQL_ENV_POSTGRES_PASSWORD}}
    DB_NAME=${DB_NAME:-${POSTGRESQL_ENV_POSTGRES_DB}}
    DB_NAME=${DB_NAME:-${POSTGRESQL_ENV_POSTGRES_USER}}

    # support for linked sameersbn/postgresql image
    DB_USER=${DB_USER:-${POSTGRESQL_ENV_DB_USER}}
    DB_PASS=${DB_PASS:-${POSTGRESQL_ENV_DB_PASS}}
    DB_NAME=${DB_NAME:-${POSTGRESQL_ENV_DB_NAME}}

    # support for linked orchardup/postgresql image
    DB_USER=${DB_USER:-${POSTGRESQL_ENV_POSTGRESQL_USER}}
    DB_PASS=${DB_PASS:-${POSTGRESQL_ENV_POSTGRESQL_PASS}}
    DB_NAME=${DB_NAME:-${POSTGRESQL_ENV_POSTGRESQL_DB}}

    # support for linked paintedfox/postgresql image
    DB_USER=${DB_USER:-${POSTGRESQL_ENV_USER}}
    DB_PASS=${DB_PASS:-${POSTGRESQL_ENV_PASS}}
    DB_NAME=${DB_NAME:-${POSTGRESQL_ENV_DB}}
  fi

  if [[ -z ${DB_HOST} ]]; then
    echo
    echo "ERROR: "
    echo "  Please configure the database connection."
    echo "  Refer http://git.io/wkYhyA for more information."
    echo "  Cannot continue without a database. Aborting..."
    echo
    return 1
  fi

  # set default port number if not specified
  DB_ADAPTER=${DB_ADAPTER:-postgresql}
  case ${DB_ADAPTER} in
    mysql2)
      DB_ENCODING=${DB_ENCODING:-utf8}
      DB_PORT=${DB_PORT:-3306}
      ;;
    postgresql)
      DB_ENCODING=${DB_ENCODING:-unicode}
      DB_PORT=${DB_PORT:-5432}
      ;;
    *)
      echo
      echo "ERROR: "
      echo "  Please specify the database type in use via the DB_ADAPTER configuration option."
      echo "  Accepted values are \"postgresql\" or \"mysql2\". Aborting..."
      echo
      return 1
      ;;
  esac

  # set default user and database
  DB_USER=${DB_USER:-pontoon}
  DB_NAME=${DB_NAME:-pontoon_production}
}


gitlab_configure_database() {
  echo -n "Configuring gitlab::database"

  gitlab_finalize_database_parameters
  gitlab_check_database_connection

  update_template ${GITLAB_DATABASE_CONFIG} \
    DB_ADAPTER \
    DB_ENCODING \
    DB_HOST \
    DB_PORT \
    DB_NAME \
    DB_USER \
    DB_PASS \
    DB_POOL

  if [[ ${DB_ADAPTER} == postgresql ]]; then
    exec_as_git sed -i \
      -e "/reconnect: /d" \
      -e "/collation: /d" \
      ${GITLAB_DATABASE_CONFIG}
  fi
}

gitlab_finalize_redis_parameters() {
  # is a redis container linked?
  if [[ -n ${REDISIO_PORT_6379_TCP_ADDR} ]]; then
    REDIS_HOST=${REDIS_HOST:-${REDISIO_PORT_6379_TCP_ADDR}}
    REDIS_PORT=${REDIS_PORT:-${REDISIO_PORT_6379_TCP_PORT}}
  fi

  # set default redis port if not specified
  REDIS_PORT=${REDIS_PORT:-6379}

  if [[ -z ${REDIS_HOST} ]]; then
    echo
    echo "ERROR: "
    echo "  Please configure the redis connection."
    echo "  Refer http://git.io/PMnRSw for more information."
    echo "  Cannot continue without a redis connection. Aborting..."
    echo
    return 1
  fi
}

gitlab_check_redis_connection() {
  timeout=60
  while ! redis-cli -h ${REDIS_HOST} -p ${REDIS_PORT} ping >/dev/null 2>&1
  do
    timeout=$(expr $timeout - 1)
    if [[ $timeout -eq 0 ]]; then
      echo ""
      echo "Could not connect to redis server. Aborting..."
      return 1
    fi
    echo -n "."
    sleep 1
  done
  echo
}

gitlab_configure_redis() {
  echo -n "Configuring gitlab::redis"

  gitlab_finalize_redis_parameters
  gitlab_check_redis_connection

  update_template ${GITLAB_RESQUE_CONFIG} \
    REDIS_HOST \
    REDIS_PORT
}

nginx_configure_gitlab_ssl() {
  if [[ ${GITLAB_HTTPS} == true && -f ${SSL_CERTIFICATE_PATH} && -f ${SSL_KEY_PATH} && -f ${SSL_DHPARAM_PATH} ]]; then
    echo "Configuring nginx::gitlab::ssl..."

    if [[ ! -f ${SSL_CA_CERTIFICATES_PATH} ]]; then
      sed -i "/{{SSL_CA_CERTIFICATES_PATH}}/d" ${GITLAB_NGINX_CONFIG}
    fi
    update_template ${GITLAB_NGINX_CONFIG} \
      SSL_CERTIFICATE_PATH \
      SSL_KEY_PATH \
      SSL_DHPARAM_PATH \
      SSL_VERIFY_CLIENT \
      SSL_CA_CERTIFICATES_PATH
  fi
}

nginx_configure_gitlab_hsts() {
  if [[ ${GITLAB_HTTPS} == true ]]; then
    echo "Configuring nginx::gitlab::hsts..."
    if [[ ${NGINX_HSTS_ENABLED} != true ]]; then
      sed -i "/{{NGINX_HSTS_MAXAGE}}/d" ${GITLAB_NGINX_CONFIG}
    fi
    update_template ${GITLAB_NGINX_CONFIG} NGINX_HSTS_MAXAGE
  else
    sed -i "/{{NGINX_HSTS_MAXAGE}}/d" ${GITLAB_NGINX_CONFIG}
  fi
}

nginx_configure_gitlab_relative_url() {
  if [[ -n ${GITLAB_RELATIVE_URL_ROOT} ]]; then
    echo "Configuring nginx::gitlab::relative_url..."
    GITLAB_RELATIVE_URL_ROOT__with_trailing_slash=${GITLAB_RELATIVE_URL_ROOT}/
    GITLAB_RELATIVE_URL_ROOT__without_trailing_slash=${GITLAB_RELATIVE_URL_ROOT}
  else
    GITLAB_RELATIVE_URL_ROOT__with_trailing_slash=/
    GITLAB_RELATIVE_URL_ROOT__without_trailing_slash=/
  fi
  update_template ${GITLAB_NGINX_CONFIG} \
    GITLAB_RELATIVE_URL_ROOT__with_trailing_slash \
    GITLAB_RELATIVE_URL_ROOT__without_trailing_slash
}

nginx_configure_gitlab_ipv6() {
  if [[ ! -f /proc/net/if_inet6 ]]; then
    # disable ipv6 support
    sed -i \
      -e "/listen \[::\]:80/d" \
      -e "/listen \[::\]:443/d" \
      ${GITLAB_NGINX_CONFIG}
  fi
}

nginx_configure_gitlab() {
  echo "Configuring nginx::gitlab..."
  update_template ${GITLAB_NGINX_CONFIG} \
    GITLAB_INSTALL_DIR \
    GITLAB_LOG_DIR \
    GITLAB_HOST \
    GITLAB_PORT \
    NGINX_PROXY_BUFFERING \
    NGINX_ACCEL_BUFFERING \
    NGINX_X_FORWARDED_PROTO

  nginx_configure_gitlab_ssl
  nginx_configure_gitlab_hsts
  nginx_configure_gitlab_relative_url
  nginx_configure_gitlab_ipv6
}

nginx_configure_gitlab_ci() {
  if [[ -n $GITLAB_CI_HOST ]]; then
    echo "Configuring nginx::gitlab_ci..."
    DNS_RESOLVERS=$(cat /etc/resolv.conf  | grep '^\s*nameserver' | awk '{print $2}' ORS=' ')
    update_template ${GITLAB_CI_NGINX_CONFIG} \
      GITLAB_LOG_DIR \
      GITLAB_HOST \
      GITLAB_CI_HOST \
      DNS_RESOLVERS
  fi
}

#   _|_|_|              _|        _|  _|
#   _|    _|  _|    _|  _|_|_|    _|        _|_|_|
#   _|_|_|    _|    _|  _|    _|  _|  _|  _|
#   _|        _|    _|  _|    _|  _|  _|  _|
#   _|          _|_|_|  _|_|_|    _|  _|    _|_|_|

map_uidgid() {
  USERMAP_ORIG_UID=$(id -u ${GITLAB_USER})
  USERMAP_ORIG_GID=$(id -g ${GITLAB_USER})
  USERMAP_GID=${USERMAP_GID:-${USERMAP_UID:-$USERMAP_ORIG_GID}}
  USERMAP_UID=${USERMAP_UID:-$USERMAP_ORIG_UID}
  if [[ ${USERMAP_UID} != ${USERMAP_ORIG_UID} ]] || [[ ${USERMAP_GID} != ${USERMAP_ORIG_GID} ]]; then
    echo "Mapping UID and GID for ${GITLAB_USER}:${GITLAB_USER} to $USERMAP_UID:$USERMAP_GID"
    groupmod -g ${USERMAP_GID} ${GITLAB_USER}
    sed -i -e "s|:${USERMAP_ORIG_UID}:${USERMAP_GID}:|:${USERMAP_UID}:${USERMAP_GID}:|" /etc/passwd
    find ${GITLAB_HOME} -path ${GITLAB_DATA_DIR}/\* -prune -o -print0 | xargs -0 chown -h ${GITLAB_USER}:
  fi
}

update_ca_certificates() {
  if [[ -f ${SSL_CERTIFICATE_PATH} || -f ${SSL_CA_CERTIFICATES_PATH} ]]; then
    echo "Updating CA certificates..."
    [[ -f ${SSL_CERTIFICATE_PATH} ]] && cp "${SSL_CERTIFICATE_PATH}" /usr/local/share/ca-certificates/gitlab.crt
    [[ -f ${SSL_CA_CERTIFICATES_PATH} ]] && cp "${SSL_CA_CERTIFICATES_PATH}" /usr/local/share/ca-certificates/ca.crt
    update-ca-certificates --fresh >/dev/null
  fi
}

initialize_logdir() {
  echo "Initializing logdir..."
  mkdir -p ${GITLAB_LOG_DIR}/supervisor
  chmod -R 0755 ${GITLAB_LOG_DIR}/supervisor
  chown -R root: ${GITLAB_LOG_DIR}/supervisor

  mkdir -p ${GITLAB_LOG_DIR}/nginx
  chmod -R 0755 ${GITLAB_LOG_DIR}/nginx
  chown -R ${GITLAB_USER}: ${GITLAB_LOG_DIR}/nginx

  mkdir -p ${GITLAB_LOG_DIR}/gitlab
  chmod -R 0755 ${GITLAB_LOG_DIR}/gitlab
  chown -R ${GITLAB_USER}: ${GITLAB_LOG_DIR}/gitlab

  mkdir -p ${GITLAB_LOG_DIR}/gitlab-shell
  chmod -R 0755 ${GITLAB_LOG_DIR}/gitlab-shell
  chown -R ${GITLAB_USER}: ${GITLAB_LOG_DIR}/gitlab-shell
}

initialize_datadir() {
  echo "Initializing datadir..."
  chmod 755 ${GITLAB_DATA_DIR}
  chown ${GITLAB_USER}: ${GITLAB_DATA_DIR}

  # create the ssh directory for server keys
  mkdir -p ${GITLAB_DATA_DIR}/ssh
  chown -R root: ${GITLAB_DATA_DIR}/ssh

  # create the repositories directory and make sure it has the right permissions
  mkdir -p ${GITLAB_REPOS_DIR}
  chown ${GITLAB_USER}: ${GITLAB_REPOS_DIR}
  chmod ug+rwX,o-rwx ${GITLAB_REPOS_DIR}
  exec_as_git chmod g+s ${GITLAB_REPOS_DIR}

  # create build traces directory
  mkdir -p ${GITLAB_BUILDS_DIR}
  chmod u+rwX ${GITLAB_BUILDS_DIR}
  chown ${GITLAB_USER}: ${GITLAB_BUILDS_DIR}

  # gitlab:backup:create does not respect the builds_path configuration, so we
  # symlink ${GITLAB_INSTALL_DIR}/builds -> ${GITLAB_BUILDS_DIR}
  rm -rf ${GITLAB_INSTALL_DIR}/builds
  ln -sf ${GITLAB_BUILDS_DIR} ${GITLAB_INSTALL_DIR}/builds

  # create downloads directory
  mkdir -p ${GITLAB_DOWNLOADS_DIR}
  chmod u+rwX ${GITLAB_DOWNLOADS_DIR}
  chown ${GITLAB_USER}: ${GITLAB_DOWNLOADS_DIR}

  # create shared directory
  mkdir -p ${GITLAB_SHARED_DIR}
  chmod u+rwX ${GITLAB_SHARED_DIR}
  chown ${GITLAB_USER}: ${GITLAB_SHARED_DIR}

  mkdir -p ${GITLAB_ARTIFACTS_DIR}
  chmod u+rwX ${GITLAB_ARTIFACTS_DIR}
  chown ${GITLAB_USER}: ${GITLAB_ARTIFACTS_DIR}

  # symlink ${GITLAB_INSTALL_DIR}/shared -> ${GITLAB_DATA_DIR}/shared
  rm -rf ${GITLAB_INSTALL_DIR}/shared
  ln -sf ${GITLAB_SHARED_DIR} ${GITLAB_INSTALL_DIR}/shared

  # create lfs-objects directory
  mkdir -p ${GITLAB_LFS_OBJECTS_DIR}
  chmod u+rwX ${GITLAB_LFS_OBJECTS_DIR}
  chown ${GITLAB_USER}: ${GITLAB_LFS_OBJECTS_DIR}

  # create the backups directory
  mkdir -p ${GITLAB_BACKUP_DIR}
  chown ${GITLAB_USER}: ${GITLAB_BACKUP_DIR}

  # create the uploads directory
  mkdir -p ${GITLAB_DATA_DIR}/uploads
  chmod 0750 ${GITLAB_DATA_DIR}/uploads
  chown ${GITLAB_USER}: ${GITLAB_DATA_DIR}/uploads

  # create the .ssh directory
  mkdir -p ${GITLAB_DATA_DIR}/.ssh
  touch ${GITLAB_DATA_DIR}/.ssh/authorized_keys
  chmod 700 ${GITLAB_DATA_DIR}/.ssh
  chmod 600 ${GITLAB_DATA_DIR}/.ssh/authorized_keys
  chown -R ${GITLAB_USER}: ${GITLAB_DATA_DIR}/.ssh
}

sanitize_datadir() {
  echo "Sanitizing datadir. Please be patient..."
  chmod -R ug+rwX,o-rwx ${GITLAB_REPOS_DIR}/
  chmod -R ug-s ${GITLAB_REPOS_DIR}/
  find ${GITLAB_REPOS_DIR}/ -type d -print0 | xargs -0 chmod g+s
  chown -R ${GITLAB_USER}: ${GITLAB_REPOS_DIR}

  chmod -R u+rwX ${GITLAB_BUILDS_DIR}
  chown -R ${GITLAB_USER}: ${GITLAB_BUILDS_DIR}

  chmod -R u+rwX ${GITLAB_DOWNLOADS_DIR}
  chown -R ${GITLAB_USER}: ${GITLAB_DOWNLOADS_DIR}

  chmod -R u+rwX ${GITLAB_TEMP_DIR}
  chown -R ${GITLAB_USER}: ${GITLAB_TEMP_DIR}

  chmod -R u+rwX ${GITLAB_SHARED_DIR}
  chown -R ${GITLAB_USER}: ${GITLAB_SHARED_DIR}

  chmod -R u+rwX ${GITLAB_ARTIFACTS_DIR}
  chown -R ${GITLAB_USER}: ${GITLAB_ARTIFACTS_DIR}

  chmod -R u+rwX ${GITLAB_LFS_OBJECTS_DIR}
  chown -R ${GITLAB_USER}: ${GITLAB_LFS_OBJECTS_DIR}

  find ${GITLAB_DATA_DIR}/uploads -type f -exec chmod 0644 {} \;
  find ${GITLAB_DATA_DIR}/uploads -type d -not -path ${GITLAB_DATA_DIR}/uploads -exec chmod 0755 {} \;
  chmod 0750 ${GITLAB_DATA_DIR}/uploads/
  chown ${GITLAB_USER}: ${GITLAB_DATA_DIR}/uploads/

  echo "Creating gitlab-shell hooks..."
  exec_as_git ${GITLAB_SHELL_INSTALL_DIR}/bin/create-hooks
}

generate_ssh_key() {
  echo -n "${1^^} "
  ssh-keygen -qt ${1} -N '' -f ${2}
}

generate_ssh_host_keys() {
  sed -i "s|HostKey /etc/ssh/|HostKey ${GITLAB_DATA_DIR}/ssh/|g" /etc/ssh/sshd_config
  if [[ ! -e ${GITLAB_DATA_DIR}/ssh/ssh_host_rsa_key ]]; then
    echo -n "Generating OpenSSH host keys... "
    generate_ssh_key rsa1     ${GITLAB_DATA_DIR}/ssh/ssh_host_key
    generate_ssh_key rsa      ${GITLAB_DATA_DIR}/ssh/ssh_host_rsa_key
    generate_ssh_key dsa      ${GITLAB_DATA_DIR}/ssh/ssh_host_dsa_key
    generate_ssh_key ecdsa    ${GITLAB_DATA_DIR}/ssh/ssh_host_ecdsa_key
    generate_ssh_key ed25519  ${GITLAB_DATA_DIR}/ssh/ssh_host_ed25519_key
    echo
  fi

  # ensure existing host keys have the right permissions
  chmod 0600 ${GITLAB_DATA_DIR}/ssh/*_key
  chmod 0644 ${GITLAB_DATA_DIR}/ssh/*.pub
}

initialize_system() {
  map_uidgid
  initialize_logdir
  initialize_datadir
  update_ca_certificates
  generate_ssh_host_keys
  install_configuration_templates
  rm -rf /var/run/supervisor.sock
}

install_configuration_templates() {
  echo "Installing configuration templates..."
  install_template ${GITLAB_USER}: gitlabhq/gitlab.yml ${GITLAB_CONFIG} 0640
  install_template ${GITLAB_USER}: gitlabhq/database.yml ${GITLAB_DATABASE_CONFIG} 0640
  install_template ${GITLAB_USER}: gitlabhq/unicorn.rb ${GITLAB_UNICORN_CONFIG} 0644
  install_template ${GITLAB_USER}: gitlabhq/rack_attack.rb ${GITLAB_RACK_ATTACK_CONFIG} 0644
  install_template ${GITLAB_USER}: gitlabhq/resque.yml ${GITLAB_RESQUE_CONFIG} 0640
  install_template ${GITLAB_USER}: gitlabhq/secrets.yml ${GITLAB_SECRETS_CONFIG} 0600
  install_template ${GITLAB_USER}: gitlab-shell/config.yml ${GITLAB_SHELL_CONFIG} 0640

  if [[ ${SMTP_ENABLED} == true  ]]; then
    install_template ${GITLAB_USER}: gitlabhq/smtp_settings.rb ${GITLAB_SMTP_CONFIG}
  fi

  # custom user specified robots.txt
  if [[ -f ${GITLAB_ROBOTS_PATH} ]]; then
    exec_as_git cp ${GITLAB_ROBOTS_PATH} ${GITLAB_ROBOTS_CONFIG}
  fi

  ## ${GITLAB_NGINX_CONFIG}
  if [[ ${GITLAB_HTTPS} == true ]]; then
    if [[ -f ${SSL_CERTIFICATE_PATH} && -f ${SSL_KEY_PATH} && -f ${SSL_DHPARAM_PATH} ]]; then
      install_template root: nginx/gitlab-ssl ${GITLAB_NGINX_CONFIG}
    else
      echo "SSL keys and certificates were not found."
      echo "Assuming that the container is running behind a HTTPS enabled load balancer."
      install_template root: nginx/gitlab ${GITLAB_NGINX_CONFIG}
    fi
  else
    install_template root: nginx/gitlab ${GITLAB_NGINX_CONFIG}
  fi

  if [[ -n $GITLAB_CI_HOST ]]; then
    install_template root: nginx/gitlab_ci ${GITLAB_CI_NGINX_CONFIG}
  fi
}

configure_gitlab() {
  echo "Configuring gitlab..."
  update_template ${GITLAB_CONFIG} \
    GITLAB_INSTALL_DIR \
    GITLAB_SHELL_INSTALL_DIR \
    GITLAB_DATA_DIR \
    GITLAB_REPOS_DIR \
    GITLAB_DOWNLOADS_DIR \
    GITLAB_SHARED_DIR \
    GITLAB_HOST \
    GITLAB_PORT \
    GITLAB_RELATIVE_URL_ROOT \
    GITLAB_HTTPS \
    GITLAB_MAX_OBJECT_SIZE \
    GITLAB_SSH_HOST \
    GITLAB_SSH_PORT \
    GITLAB_USERNAME_CHANGE \
    GITLAB_CREATE_GROUP \
    GITLAB_TIMEOUT

  gitlab_configure_database
  gitlab_configure_redis
  gitlab_configure_secrets
  gitlab_configure_sidekiq
  gitlab_configure_gitlab_workhorse
  gitlab_configure_unicorn
  gitlab_configure_timezone
  gitlab_configure_rack_attack
  gitlab_configure_ci
  gitlab_configure_artifacts
  gitlab_configure_lfs
  gitlab_configure_project_features
  gitlab_configure_mail_delivery
  gitlab_configure_mailroom
  gitlab_configure_oauth
  gitlab_configure_ldap
  gitlab_configure_gravatar
  gitlab_configure_analytics
  gitlab_configure_backups
}

configure_gitlab_shell() {
  echo "Configuring gitlab-shell..."
  update_template ${GITLAB_SHELL_CONFIG} \
    GITLAB_RELATIVE_URL_ROOT \
    GITLAB_HOME \
    GITLAB_LOG_DIR \
    GITLAB_DATA_DIR \
    GITLAB_BACKUP_DIR \
    GITLAB_REPOS_DIR \
    GITLAB_SHELL_INSTALL_DIR \
    SSL_SELF_SIGNED \
    REDIS_HOST \
    REDIS_PORT
}

configure_nginx() {
  echo "Configuring nginx..."
  sed -i "s|worker_processes .*|worker_processes ${NGINX_WORKERS};|" /etc/nginx/nginx.conf
  nginx_configure_gitlab
  nginx_configure_gitlab_ci
}

migrate_database() {
  # run the `gitlab:setup` rake task if required
  case ${DB_ADAPTER} in
    mysql2)
      QUERY="SELECT count(*) FROM information_schema.tables WHERE table_schema = '${DB_NAME}';"
      COUNT=$(mysql -h ${DB_HOST} -P ${DB_PORT} -u ${DB_USER} ${DB_PASS:+-p$DB_PASS} -ss -e "${QUERY}")
      ;;
    postgresql)
      QUERY="SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public';"
      COUNT=$(PGPASSWORD="${DB_PASS}" psql -h ${DB_HOST} -p ${DB_PORT} -U ${DB_USER} -d ${DB_NAME} -Atw -c "${QUERY}")
      ;;
  esac
  if [[ -z ${COUNT} || ${COUNT} -eq 0 ]]; then
    echo "Setting up GitLab for firstrun. Please be patient, this could take a while..."
    exec_as_git force=yes bundle exec rake gitlab:setup ${GITLAB_ROOT_PASSWORD:+GITLAB_ROOT_PASSWORD=$GITLAB_ROOT_PASSWORD} >/dev/null
  fi

  # migrate database if the gitlab version has changed.
  CACHE_VERSION=
  [[ -f ${GITLAB_TEMP_DIR}/VERSION ]] && CACHE_VERSION=$(cat ${GITLAB_TEMP_DIR}/VERSION)
  if [[ ${GITLAB_VERSION} != ${CACHE_VERSION} ]]; then
    ## version check, only upgrades are allowed
    if [[ -n ${CACHE_VERSION} && $(vercmp ${GITLAB_VERSION} ${CACHE_VERSION}) -lt 0 ]]; then
      echo
      echo "ERROR: "
      echo "  Cannot downgrade from GitLab version ${CACHE_VERSION} to ${GITLAB_VERSION}."
      echo "  Only upgrades are allowed. Please use sameersbn/gitlab:${CACHE_VERSION} or higher."
      echo "  Cannot continue. Aborting!"
      echo
      return 1
    fi

    if [[ $(vercmp ${GITLAB_VERSION} 8.0.0) -gt 0 ]]; then
      if [[ -n ${CACHE_VERSION} && $(vercmp ${CACHE_VERSION} 8.0.0) -lt 0 ]]; then
        echo
        echo "ABORT: "
        echo "  Upgrading to GitLab ${GITLAB_VERSION} from ${CACHE_VERSION} is not recommended."
        echo "  Please upgrade to version 8.0.5-1 before upgrading to 8.1.0 or higher."
        echo "  Refer to https://git.io/vur4j for CI migration instructions."
        echo "  Aborting for your own safety!"
        echo
        return 1
      fi
    fi

    echo "Migrating database..."
    exec_as_git bundle exec rake db:migrate >/dev/null

    if [[ ${DB_ADAPTER} == mysql2 ]]; then
      exec_as_git bundle exec rake add_limits_mysql >/dev/null
    fi

    echo "${GITLAB_VERSION}" > ${GITLAB_TEMP_DIR}/VERSION
    rm -rf ${GITLAB_TEMP_DIR}/GITLAB_RELATIVE_URL_ROOT # force cache cleanup
  fi

  # clear cache if relative_url has changed.
  [[ -f ${GITLAB_DATA_DIR}/tmp/GITLAB_RELATIVE_URL_ROOT ]] && CACHE_GITLAB_RELATIVE_URL_ROOT=$(cat ${GITLAB_DATA_DIR}/tmp/GITLAB_RELATIVE_URL_ROOT)
  if [[ ! -f ${GITLAB_DATA_DIR}/tmp/GITLAB_RELATIVE_URL_ROOT || ${GITLAB_RELATIVE_URL_ROOT} != ${CACHE_GITLAB_RELATIVE_URL_ROOT} ]]; then
    echo "Clearing cache..."
    exec_as_git bundle exec rake cache:clear >/dev/null 2>&1
    echo "${GITLAB_RELATIVE_URL_ROOT}" > ${GITLAB_TEMP_DIR}/GITLAB_RELATIVE_URL_ROOT
  fi
}

execute_raketask() {
  if [[ -z ${1} ]]; then
    echo "Please specify the rake task to execute. See https://github.com/gitlabhq/gitlabhq/tree/master/doc/raketasks"
    return 1
  fi

  if [[ ${1} == gitlab:backup:restore ]]; then
    interactive=true
    for arg in $@
    do
      if [[ $arg == BACKUP=* ]]; then
        interactive=false
        break
      fi
    done

    # user needs to select the backup to restore
    if [[ $interactive == true ]]; then
      nBackups=$(ls ${GITLAB_BACKUP_DIR}/*_gitlab_backup.tar | wc -l)
      if [[ $nBackups -eq 0 ]]; then
        echo "No backup present. Cannot continue restore process.".
        return 1
      fi

      echo
      for b in $(ls ${GITLAB_BACKUP_DIR} | grep _gitlab_backup | sort -r)
      do
        echo "‣ $b (created at $(date --date="@${b%%_gitlab_backup.tar}" +'%d %b, %G - %H:%M:%S %Z'))"
      done
      echo

      read -p "Select a backup to restore: " file

      if [[ -z ${file} ]]; then
        echo "Backup not specified. Exiting..."
        return 1
      fi

      if [[ ! -f ${GITLAB_BACKUP_DIR}/${file} ]]; then
        echo "Specified backup does not exist. Aborting..."
        return 1
      fi

      BACKUP=${file%%_gitlab_backup.tar}
    fi
  elif [[ ${1} == gitlab:import:repos ]]; then
    # sanitize the datadir to avoid permission issues
    sanitize_datadir
  fi
  echo "Running raketask ${1}..."
  exec_as_git bundle exec rake $@ ${BACKUP:+BACKUP=$BACKUP}
}