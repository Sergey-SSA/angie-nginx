# http-контекст - зоны ограничения по подключениям с одного IP и по количеству подключений к виртуальному серверу

limit_conn_zone $binary_remote_addr zone=perip:10m;
limit_conn_zone $server_name zone=perserver:10m;

# Активируем ограничения в блоке server (или location)
server {
    ...
    limit_conn perip 10;
    limit_conn perserver 100;
}

# Проверка
ab -n 200 -c 8 -l -k -H "Accept-Encoding: gzip,deflate,br" https://test.metodlab.ru/
wrk -t4 -c10 -d10s --latency -H "Accept-Encoding: gzip,deflate,br" https://test.metodlab.ru/

# Базовая аутентификация

auth_basic           "Identify yourself!";
auth_basic_user_file /etc/angie/htpasswd;


# Работа с паролями
# htpasswd (из пакета Apache)
htpasswd /etc/angie/htpasswd newuser
htpasswd -c /etc/angie/htpasswd newuser

# С помощью OpenSSL
echo -n 'testuser:' >> /etc/angie/.htpasswd
openssl passwd -apr1 >> /etc/angie/.htpasswd


# Совместное использование
satisfy any;
allow 192.168.0.0/24;
deny  192.168.0.100;
deny  all;
auth_basic           "Identify yourself!";
auth_basic_user_file /etc/angie/htpasswd;

# Fail2Ban
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
nano jail.local
[nginx-limit-req]

port    = http,https
enabled = true
filter = nginx-limit-req
action = iptables-multiport[name=ReqLimit, port="http,https", protocol=tcp]
logpath = /var/log/angie/*error.log
findtime = 600
bantime = 7200
maxretry = 4

# User-Agent блокировки
map $http_user_agent $limit_search_bots {
		default 0;
		~*(google|bing|yandex|msnbot) 1;
	}

if ($limit_bots = 1) {
    return 444;
}

# Iptables блокировки
iptables -I INPUT -s 10.26.95.20 -j DROP
# Лучше:
iptables -t raw -I PREROUTING -s 10.26.95.20 -j DROP
# Можно сеть целиком:
iptables -t raw -I PREROUTING -s 10.26.95.0/24 -j DROP

# IPset
# Создать (отдельные IP):
ipset -N ddos iphash
#Создать (подсети):
ipset create blacklist nethash
#Добавить подсеть:
ipset -A ddos 109.95.48.0/21
#Посмотреть список:
ipset -L ddos
#Проверить:
ipset test ddos 185.174.102.1
#Сохранение:
sudo ipset save blacklist -f ipset-blacklist.backup
#Восстановление:
sudo ipset restore -! < ipset-blacklist.backup
#Очистка: 
sudo ipset flush blacklist
#Правило:
iptables -I PREROUTING -t raw -m set --match-set ddos src -j DROP
#Сохранение постоянно:
apt install ipset-persistent

# NFtables блокировка
nft add set ip filter blackhole { type ipv4_addr\; flags interval; auto-merge; policy memory; comment \"drop all packets from these hosts\" \; }
nft add element ip filter blackhole { 192.168.3.4 }
nft add element ip filter blackhole { 192.168.1.4, 192.168.1.5 }
nft add rule ip filter input ip saddr @blackhole drop
nft add rule ip filter output ip daddr != @blackhole accept
nft get element ip filter blackhole { 1.1.1.1 }

# Показать правила без наборов
nft -t list ruleset
