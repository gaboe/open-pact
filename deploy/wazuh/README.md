# Wazuh file input

The sample [agent-localfile.xml](agent-localfile.xml) reads JSON events from `/var/log/open-pact/events.jsonl`. The [rsyslog.conf](rsyslog.conf) sample writes TLS messages to that file on the receiver host.

You can also set `GATEWAY_SIEM_FILE` when the gateway and Wazuh agent run on the same host. Set `GATEWAY_SIEM_FILE_MODE=0640` to let the agent's group read new files. Add the gateway process to that group. Give the directory group read and execute access. Keep the gateway as the file's only writer.

Use the TLS receiver or the direct file sink for a given path. Do not configure both to write the same file. External rotation can rename the file. The gateway creates the replacement with the configured mode on its next write.
