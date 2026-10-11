#!/bin/sh
# Prepares one variant of container state, then prints the Linux check results.
# All sample data is fictional. A shim stands in for a tool only where a
# container cannot run the real one (systemd); each shim is named below.
set -u
variant=${1:-baseline}
shims=/tmp/shims
mkdir -p "$shims"
PATH="$shims:$PATH"

shim() { # name, body
    printf '#!/bin/sh\n%s\n' "$2" >"$shims/$1"
    chmod +x "$shims/$1"
}

. /etc/os-release
distro=$ID

# Baseline hides the firewalld client so "no firewall tooling" is a real state.
case $variant in
    firewalld-installed) ;;
    *) command -v firewall-cmd >/dev/null && mv "$(command -v firewall-cmd)" /tmp/firewall-cmd.hidden ;;
esac

set_gsettings() { # lock-enabled idle-delay lock-delay
    export GSETTINGS_BACKEND=keyfile XDG_CURRENT_DESKTOP=GNOME
    gsettings set org.gnome.desktop.screensaver lock-enabled "$1"
    gsettings set org.gnome.desktop.session idle-delay "$2"
    gsettings set org.gnome.desktop.screensaver lock-delay "$3"
}

ufw_conf() { # yes|no
    mkdir -p /etc/ufw
    printf '# fictional ufw.conf\nENABLED=%s\nLOGLEVEL=low\n' "$1" >/etc/ufw/ufw.conf
}

stale_history() {
    if [ "$distro" = fedora ]; then
        shim dnf 'cat <<DNF
ID Command line                Date and time       Action(s)  Altered
 12 upgrade                    2024-01-09 08:15:02 Upgrade         3
 11 install example-tool       2024-01-02 09:00:00 Install         1
DNF'
    else
        mkdir -p /var/log/apt
        printf 'Start-Date: 2024-01-09  08:14:00\nCommandline: apt upgrade\nUpgrade: example-lib:amd64 (1.0, 1.1)\nEnd-Date: 2024-01-09  08:15:02\n' >/var/log/apt/history.log
    fi
}

case $variant in
    baseline) ;;
    firewalld-installed) ;;
    ufw-active) ufw_conf yes
        shim systemctl '[ "$1 $2" = "is-active ufw" ] && echo active || echo inactive' ;;
    ufw-active-disabled) ufw_conf no
        shim systemctl '[ "$1 $2" = "is-active ufw" ] && echo active || echo inactive' ;;
    ufw-inactive) shim systemctl 'echo inactive; exit 3' ;;
    gnome-default) export GSETTINGS_BACKEND=keyfile XDG_CURRENT_DESKTOP=GNOME ;;
    gnome-lock-5min) set_gsettings true 300 0 ;;
    gnome-lock-15min) set_gsettings true 900 0 ;;
    gnome-lock-off) set_gsettings false 300 0 ;;
    kde-5min) export XDG_CURRENT_DESKTOP=KDE; mkdir -p "$HOME/.config"
        printf '[Daemon]\nAutolock=true\nTimeout=5\n' >"$HOME/.config/kscreenlockerrc" ;;
    kde-30min) export XDG_CURRENT_DESKTOP=KDE; mkdir -p "$HOME/.config"
        printf '[Daemon]\nAutolock=true\nTimeout=30\n' >"$HOME/.config/kscreenlockerrc" ;;
    kde-off) export XDG_CURRENT_DESKTOP=KDE; mkdir -p "$HOME/.config"
        printf '[Daemon]\nAutolock=false\n' >"$HOME/.config/kscreenlockerrc" ;;
    patch-real) ;;
    patch-stale) stale_history ;;
    patch-rotated)
        if [ "$distro" = fedora ]; then
            stale_history
        else
            mkdir -p /var/log/apt
            printf 'Start-Date: 2026-10-02  06:00:00\nCommandline: apt install example-tool\nInstall: example-tool:amd64 (1.0)\nEnd-Date: 2026-10-02  06:00:10\n' >/var/log/apt/history.log
            printf 'Start-Date: 2024-01-09  08:14:00\nCommandline: apt upgrade\nUpgrade: example-lib:amd64 (1.0, 1.1)\nEnd-Date: 2024-01-09  08:15:02\n' | gzip >/var/log/apt/history.log.1.gz
        fi ;;
    eol)
        if [ "$distro" = fedora ]; then
            printf 'NAME="Fedora Linux"\nVERSION_ID=38\nID=fedora\n' >/etc/os-release
        else
            printf 'NAME="Ubuntu"\nVERSION_ID="20.04"\nID=ubuntu\nID_LIKE=debian\n' >/etc/os-release
        fi ;;
    autologin-gdm)
        mkdir -p /etc/gdm3 /etc/gdm
        printf '[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=testuser\n' >/etc/gdm3/custom.conf
        cp /etc/gdm3/custom.conf /etc/gdm/custom.conf ;;
    autologin-lightdm)
        mkdir -p /etc/lightdm
        printf '[Seat:*]\nautologin-user = testuser\n' >/etc/lightdm/lightdm.conf ;;
    autologin-off)
        mkdir -p /etc/gdm3 /etc/gdm
        printf '[daemon]\n#  AutomaticLoginEnable = true\n' >/etc/gdm3/custom.conf
        cp /etc/gdm3/custom.conf /etc/gdm/custom.conf ;;
    autologin-sddm)
        printf '[Autologin]\nUser=testuser\nSession=plasma\n' >/etc/sddm.conf ;;
    clamav-active) shim systemctl 'echo inactive; echo active' ;;
    clamav-inactive) shim systemctl 'echo inactive; echo inactive; exit 3' ;;
    *) echo "unknown variant $variant" >&2; exit 2 ;;
esac

start=$(date +%s%N)
out=$(open-pact-checks print_run_all_on_this_machine --ignored --nocapture --test-threads=1 2>/tmp/stderr)
status=$?
end=$(date +%s%N)
echo "$out" | sed -n 's/^\(test .* \.\.\. \)\{0,1\}\([a-z_]* = .*\)$/\2/p'
echo "elapsed_ms = $(( (end - start) / 1000000 ))"
grep -q panicked /tmp/stderr && echo "panic = yes"
[ $status -eq 0 ] || { echo "exit = $status"; cat /tmp/stderr >&2; }
exit 0
