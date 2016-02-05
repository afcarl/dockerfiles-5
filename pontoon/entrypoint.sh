#!/bin/bash
set -e

#TODO: source ./functions.sh
virtualenv venv
source ./venv/bin/activate
pip install -r requirements.txt
git clone https://github.com/mozilla/pontoon-intro /pontoon/pontoon/intro 
python manage.py migrate


#TODO: put DB stuff in functions.sh 
## get postgres image linkage
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
    
    cat >> /pontoon/.dotenv << OEF
SECRET_KEY=M4w2V7DMfpVVhnEGh27DfCyyVtVxx4EB6aLMqRwLKLDEpUlbrJKNFPwKrqtlHAVc
DJANGO_DEV=True
DJANGO_DEBUG=True
DATABASE_URL=postgres://${DB_USER}:${DB_PASS}@${DB_HOST}/${DB_NAME}
SESSION_COOKIE_SECURE=False
HMAC_KEY=M4w2V7DMfpVVhnEGh27DfCyyVtVxx4EB6aLMqRwLKLDEpUlbrJKNFPwKrqtlHAVc
SITE_URL=http://localhost:8000
OEF
fi

echo 'DB CNX '
echo ${POSTGRESQL_PORT_5432_TCP_ADDR}
#python manage.py migrate
#python manage.py createsuperuser (julien.bisconti@groups.be bisconti6032)
#python manage.py sync_projects --no-commit pontoon-intro
#npm install
#ENTRYPOINT ["/sbin/entrypoint.sh"]


[[ $DEBUG == true ]] && set -x

#TODO adapt parameters/options
case ${1} in
  app:init|app:start|app:sanitize|app:rake)

    initialize_system
    configure_gitlab
    configure_gitlab_shell
    configure_nginx

    case ${1} in
      app:start)
        migrate_database
        exec /usr/bin/supervisord -nc /etc/supervisor/supervisord.conf
        ;;
      app:init)
        migrate_database
        ;;
      app:sanitize)
        sanitize_datadir
        ;;
      app:rake)
        shift 1
        execute_raketask $@
        ;;
    esac
    ;;
  app:help)
    echo "Available options:"
    echo " app:start        - Starts the gitlab server (default)"
    echo " app:init         - Initialize the gitlab server (e.g. create databases, compile assets), but don't start it."
    echo " app:sanitize     - Fix repository/builds directory permissions."
    echo " app:rake <task>  - Execute a rake task."
    echo " app:help         - Displays the help"
    echo " [command]        - Execute the specified command, eg. bash."
    ;;
  *)
    exec "$@"
    ;;
esac
