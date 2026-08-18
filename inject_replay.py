import socket, time

sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1048576)

attack_families = {'encoded_or_obfuscated', 'download', 'registry_run_key', 'credential_access'}
attack_lines = []
benign_lines = []

with open('/var/ossec/logs/replay-wazuh.log') as f:
    for line in f:
        line = line.strip()
        if line:
            if any('family=' + af in line for af in attack_families):
                attack_lines += [line]
            else:
                benign_lines += [line]

print('Attack events: ' + str(len(attack_lines)))
print('Benign events: ' + str(len(benign_lines)))

count = 0
for line in attack_lines:
    msg = 'replay-wazuh:1:' + line
    sock.sendto(msg.encode(), '/var/ossec/queue/sockets/queue')
    count += 1
    time.sleep(0.3)

print('Sent ' + str(count) + ' attack events. Waiting 3s...')
time.sleep(3)

for line in benign_lines:
    msg = 'replay-wazuh:1:' + line
    try:
        sock.sendto(msg.encode(), '/var/ossec/queue/sockets/queue')
        count += 1
    except:
        time.sleep(0.1)
        try:
            sock.sendto(msg.encode(), '/var/ossec/queue/sockets/queue')
            count += 1
        except:
            pass
    if count % 50000 == 0:
        print('Sent ' + str(count) + '...')
        time.sleep(0.5)

print('Done. Total sent: ' + str(count))
sock.close()
