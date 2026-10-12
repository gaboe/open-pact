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
        shim dnf '[ "$1" = history ] || exit 0
cat <<DNF
ID Command line                Date and time       Action(s)  Altered
 12 upgrade                    2024-01-09 08:15:02 Upgrade         3
 11 install example-tool       2024-01-02 09:00:00 Install         1
DNF'
    else
        mkdir -p /var/log/apt
        printf 'Start-Date: 2024-01-09  08:14:00\nCommandline: apt upgrade\nUpgrade: example-lib:amd64 (1.0, 1.1)\nEnd-Date: 2024-01-09  08:15:02\n' >/var/log/apt/history.log
    fi
}

fictional_archive() { # APT only: one configured fictional security archive, cached at 1.0
    arch=$(dpkg --print-architecture)
    archive=/tmp/fictional-archive
    mkdir -p "$archive" /var/log/apt
    rm -rf /etc/apt/sources.list /etc/apt/sources.list.d/* /var/lib/apt/lists/*
    mkdir -p /var/lib/apt/lists/partial
    printf 'deb [trusted=yes] file:%s ./\n' "$archive" >/etc/apt/sources.list
    printf 'Package: fictional-lib\nStatus: install ok installed\nPriority: optional\nSection: libs\nArchitecture: %s\nVersion: 1.0\nDescription: Fictional library\n\n' "$arch" >/var/lib/dpkg/status
    printf 'Start-Date: %s  06:00:00\nCommandline: apt upgrade\nUpgrade: fictional-lib:%s (0.9, 1.0)\nEnd-Date: %s  06:00:30\n' "$(date +%F)" "$arch" "$(date +%F)" >/var/log/apt/history.log
    publish 1.0
    apt-get update -qq
}

publish() { # version: the fictional archive now offers fictional-lib at that version
    printf 'Package: fictional-lib\nVersion: %s\nArchitecture: %s\nPriority: optional\nSection: libs\nFilename: fictional-lib.deb\nSize: 1234\nDescription: Fictional library\n\n' "$1" "$arch" >"$archive/Packages"
    printf 'Origin: Fictional\nLabel: Fictional-security\nSuite: fictional-security\nCodename: fictional-security\nDate: %s\nSHA256:\n %s %s Packages\n' \
        "$(date -Ru)" \
        "$(sha256sum "$archive/Packages" | cut -d' ' -f1)" "$(wc -c <"$archive/Packages")" >"$archive/Release"
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
    patch-no-metadata)
        if [ "$distro" = fedora ]; then dnf clean all >/dev/null; else rm -rf /var/lib/apt/lists/*; fi ;;
    patch-stale) stale_history ;;
    patch-expired) [ "$distro" = fedora ] || {
        fictional_archive
        publish 2.0
        for f in /var/lib/apt/lists/*_Release; do
            sed -i 's/^Date:.*/Date: Sat, 01 Jan 2000 00:00:00 +0000/' "$f"
            printf 'Valid-Until: Sun, 02 Jan 2000 00:00:00 +0000\n' >>"$f"
        done
    } ;;
    patch-apt-current) [ "$distro" = fedora ] || fictional_archive ;;
    patch-apt-pending) [ "$distro" = fedora ] || {
        fictional_archive
        publish 2.0
        apt-get update -qq
    } ;;
    patch-apt-no-packages) [ "$distro" = fedora ] || {
        fictional_archive
        publish 2.0
        apt-get update -qq
        rm /var/lib/apt/lists/*_Packages*
    } ;;
    patch-apt-orphan-release) [ "$distro" = fedora ] || {
        fictional_archive
        publish 2.0
        for f in /var/lib/apt/lists/*_Release; do mv "$f" /var/lib/apt/lists/unconfigured.invalid_dists_fictional-security_Release; done
    } ;;
    patch-apt-uncached-source) [ "$distro" = fedora ] || {
        fictional_archive
        publish 2.0
        mkdir -p /tmp/other-archive
        : >/tmp/other-archive/Packages
        printf 'Origin: Fictional\nSuite: other-security\nCodename: other-security\nDate: %s\nSHA256:\n %s 0 Packages\n' \
            "$(date -Ru)" "$(sha256sum /tmp/other-archive/Packages | cut -d' ' -f1)" >/tmp/other-archive/Release
        printf 'deb [trusted=yes] file:/tmp/other-archive ./\n' >/etc/apt/sources.list
        apt-get update -qq
        printf 'deb [trusted=yes] file:%s ./\n' "$archive" >>/etc/apt/sources.list
    } ;;
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
if grep -q panicked /tmp/stderr; then
    echo "panic = yes"
    [ $status -ne 0 ] || status=101
fi
[ $status -eq 0 ] || { echo "exit = $status"; cat /tmp/stderr >&2; }
exit $status
