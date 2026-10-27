package install

import "fmt"

const rootHelperSocketPath = "/run/nurproxy-agent-helper/helper.sock"

func RenderRootHelperUnit(binaryPath string) string {
	return fmt.Sprintf(`[Unit]
Description=NurProxy privileged recovery helper
Requires=nurproxy-agent-helper.socket
After=nurproxy-agent-helper.socket

[Service]
Type=exec
ExecStart=%s root-helper
User=root
Group=root
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectControlGroups=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectClock=true
ProtectHostname=true
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictNamespaces=true
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
`, binaryPath)
}

func RenderRootHelperSocket() string {
	return `[Unit]
Description=NurProxy privileged recovery helper socket
Before=nurproxy-agent.service

[Socket]
ListenSequentialPacket=` + rootHelperSocketPath + `
FileDescriptorName=nurproxy-agent-helper
SocketUser=nurproxy
SocketGroup=nurproxy
SocketMode=0660
DirectoryMode=0755
RemoveOnStop=true
Service=nurproxy-agent-helper.service

[Install]
WantedBy=sockets.target
`
}
