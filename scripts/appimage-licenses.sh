#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# License notices and corresponding source for the libraries ExploitX's AppImage bundles (Mission 14).
#
#   scripts/appimage-licenses.sh <out-dir> [--sources <file.tar>] [--tauri-config <file.json>]
#       <out-dir>              the copyright file of every library package, PACKAGES.tsv and README.txt
#       --sources <file.tar>   also the Debian source packages of the LGPL/GPL-licensed libraries (needs deb-src)
#       --tauri-config <file>  a Tauri configuration that puts <out-dir> into the AppImage at
#                              usr/share/doc/exploitx-appimage/ (pass it to `tauri build --config`)
#   scripts/appimage-licenses.sh --check <extracted AppImage dir> [--sources <file.tar>]
#       fails unless every shared library in the AppImage has its package's copyright file, at the listed
#       version, every license text those files refer to is there, and (with --sources) the archive holds
#       the source package of every GPL/LGPL library at the shipped version, its files matching the .dsc
#
# Runs on the Debian/Ubuntu system that builds the AppImage (the release workflow's ubuntu-22.04 runner),
# before `tauri build`: the AppImage bundler (linuxdeploy) copies the shared libraries of GTK and WebKitGTK
# from this system, so their packages, versions and licenses are this system's.
#
# What it collects is a superset of what the AppImage carries: the dependency closure of the GTK and
# WebKitGTK libraries, GTK's modules, GDK-Pixbuf loaders, GIO modules and WebKit helper processes.
# `--check` compares a built AppImage with it.
set -euo pipefail
DOC=usr/share/doc/exploitx-appimage
# glibc, the dynamic loader and the compiler runtime are never bundled (the AppImage excludelist)
EXCLUDED='^(libc6|libc-bin|libgcc-s1|libstdc\+\+6)$'

# the package that installed a file (merged /usr: dpkg may record it under /lib)
owner() {
  local pkg
  pkg=$(dpkg -S "$1" 2>/dev/null | grep -v '^diversion' | head -1 | cut -d: -f1) || true
  if [ -z "$pkg" ] && [ "${1#/usr}" != "$1" ]; then
    pkg=$(dpkg -S "${1#/usr}" 2>/dev/null | grep -v '^diversion' | head -1 | cut -d: -f1) || true
  fi
  echo "$pkg"
}

# the package whose file a bundled library was copied from: the system file whose path ends like the
# bundled one below usr/lib (GTK 2 and GTK 3 modules share file names), followed through symlinks (an
# unversioned libfoo.so is a -dev package's link to the runtime library, which is what was copied)
source_owner() {
  local rel=$1 sys
  sys=$(dpkg -S "*/$rel" 2>/dev/null | grep -v '^diversion' | head -1 | sed 's/^.*: //') || true
  [ -n "$sys" ] || sys=$(dpkg -S "*/$(basename "$rel")" 2>/dev/null | grep -v '^diversion' | head -1 | sed 's/^.*: //') || true
  [ -n "$sys" ] || return 0
  owner "$(readlink -f "$sys")"
}

if [ "${1:-}" = "--check" ]; then
  app=${2:?usage: appimage-licenses.sh --check <extracted AppImage dir> [--sources <file.tar>]}
  srctar=""
  if [ "${3:-}" = "--sources" ]; then srctar=${4:?--sources needs the source archive}; fi
  [ -f "$app/$DOC/README.txt" ] && [ -f "$app/$DOC/PACKAGES.tsv" ] || { echo "error: $app has no $DOC/README.txt and PACKAGES.tsv" >&2; exit 1; }
  missing=0
  n=0
  # 1. every bundled library: its package's copyright file, and the package at the installed version
  while IFS= read -r so; do
    n=$((n + 1))
    pkg=$(source_owner "${so#"$app"/usr/lib/}")
    if [ -z "$pkg" ]; then echo "error: no package installed $(basename "$so") (bundled as ${so#"$app"/})" >&2; missing=1; continue; fi
    echo "$pkg" | grep -q -E "$EXCLUDED" && continue
    if [ ! -s "$app/$DOC/copyright/$pkg" ]; then echo "error: ${so#"$app"/} comes from $pkg, whose copyright file is not in $DOC/copyright" >&2; missing=1; fi
    v=$(dpkg-query -W -f '${Version}' "$pkg")
    if ! awk -F'\t' -v p="$pkg" -v v="$v" '$1 == p && $2 == v { found = 1 } END { exit !found }' "$app/$DOC/PACKAGES.tsv"; then
      echo "error: ${so#"$app"/} comes from $pkg $v, which PACKAGES.tsv does not list at that version" >&2; missing=1
    fi
  done < <(find "$app/usr/lib" -type f \( -name '*.so' -o -name '*.so.*' \) | sort)
  [ "$n" -gt 0 ] || { echo "error: no shared libraries under $app/usr/lib" >&2; exit 1; }
  # 2. every license text a copyright file refers to (/usr/share/common-licenses/<name>) is in the AppImage;
  #    a reference with a ".0" the Debian file name lacks (GPL-2.0 for GPL-2, a typo in Pango's file) is
  #    satisfied by that file
  refs=0
  while IFS= read -r name; do
    refs=$((refs + 1))
    [ -s "$app/$DOC/common-licenses/$name" ] || [ -s "$app/$DOC/common-licenses/${name%.0}" ] || {
      echo "error: a copyright file refers to /usr/share/common-licenses/$name, which is not in $DOC/common-licenses" >&2; missing=1; }
  done < <({ grep -h -o '/usr/share/common-licenses/[A-Za-z0-9.+_-]*' "$app/$DOC/copyright/"* || true; } | sed 's#.*/##; s/[.]*$//' | sort -u)
  # 3. the source archive: the source package of every GPL/LGPL library, at the version its binary came
  #    from, with every file the .dsc lists present and matching its SHA-256
  if [ -n "$srctar" ]; then
    work=$(mktemp -d)
    tar -xf "$srctar" -C "$work"
    srcs=0
    while IFS=$'\t' read -r src sver; do
      srcs=$((srcs + 1))
      dsc="$work/${src}_${sver#*:}.dsc"
      if [ ! -f "$dsc" ]; then echo "error: the source archive has no ${src}_${sver#*:}.dsc (source of a GPL/LGPL library)" >&2; missing=1; continue; fi
      got=$(sed -n 's/^Version: *//p' "$dsc" | head -1)
      [ "$got" = "$sver" ] || { echo "error: $(basename "$dsc") is version $got, the shipped binary's source is $sver" >&2; missing=1; }
      while read -r sum _ file; do
        [ -f "$work/$file" ] || { echo "error: $file, listed in $(basename "$dsc"), is not in the source archive" >&2; missing=1; continue; }
        [ "$(sha256sum "$work/$file" | cut -d' ' -f1)" = "$sum" ] || { echo "error: $file does not match the SHA-256 in $(basename "$dsc")" >&2; missing=1; }
      done < <(awk '/^Checksums-Sha256:/ { f = 1; next } /^[^ ]/ { f = 0 } f && NF == 3 { print }' "$dsc")
    done < <(awk -F'\t' 'NR > 1 && $5 ~ /GPL/ { print $3 "\t" $4 }' "$app/$DOC/PACKAGES.tsv" | sort -u)
    rm -rf "$work"
  fi
  [ "$missing" = 0 ] || exit 1
  echo "all $n shared libraries in the AppImage have their package's copyright file in $DOC/copyright, at the listed versions"
  echo "all $refs license texts the copyright files refer to are in $DOC/common-licenses"
  if [ -n "$srctar" ]; then echo "all $srcs GPL/LGPL source packages are in $(basename "$srctar") at the shipped versions, their files matching the .dsc checksums"; fi
  exit 0
fi

out=${1:?usage: appimage-licenses.sh <out-dir> [--sources <file.tar>] [--tauri-config <file.json>]}
shift
sources=""
config=""
while [ $# -gt 0 ]; do
  case "$1" in
    --sources) sources=${2:?--sources needs a file}; shift 2 ;;
    --tauri-config) config=${2:?--tauri-config needs a file}; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
mkdir -p "$out/copyright"

# 1. the shared objects: the libraries and plugins the bundler starts from, then their dependency closure
seeds=$(
  {
    ldconfig -p | awk '/libwebkit2gtk-4\.1\.so\.0|libjavascriptcoregtk-4\.1\.so\.0|libgtk-3\.so\.0|librsvg-2\.so\.2|libayatana-appindicator3\.so\.1/ {print $NF}'
    # plugins the bundler copies too: GTK's input method and print modules (the CUPS backend brings
    # libcups, Avahi and colord), GDK-Pixbuf loaders, GIO modules, WebKit's helper processes
    find /usr/lib/x86_64-linux-gnu/gtk-3.0 /usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0 /usr/lib/x86_64-linux-gnu/gio/modules /usr/lib/x86_64-linux-gnu/webkit2gtk-4.1 -type f \( -name "*.so" -o -perm -u+x \) 2>/dev/null || true
  } | sort -u
)
closure=$(for f in $seeds; do echo "$f"; { ldd "$f" 2>/dev/null || true; } | awk '/=> \//{print $3}'; done | xargs -r -n1 readlink -f | sort -u)

# 2. the packages that own them
packages=$(for f in $closure; do owner "$f"; done | grep -v -E '^$' | sort -u | grep -v -E "$EXCLUDED")

# 3. each package's copyright file (a doc directory may be a symlink to another package's) and its source
{
  printf 'package\tversion\tsource package\tsource version\tlicenses named in debian/copyright\n'
  for p in $packages; do
    v=$(dpkg-query -W -f '${Version}' "$p")
    s=$(dpkg-query -W -f '${source:Package}' "$p")
    sv=$(dpkg-query -W -f '${source:Version}' "$p")
    doc=$(readlink -f "/usr/share/doc/$p" || true)
    if [ -f "$doc/copyright" ]; then
      cp "$doc/copyright" "$out/copyright/$p"
      # older copyright files are not in the machine-readable format: no License: lines, the text is still copied
      lic=$({ grep -E '^License:' "$doc/copyright" || true; } | sed 's/^License: *//' | sort -u | paste -sd ';' -)
      [ -n "$lic" ] || lic="(free-form copyright file)"
      # a GNU license named only in the text (free-form files, "other" stanzas) still needs the source:
      # the column must say so, because step 5 selects the source packages by it
      case "$lic" in *GPL*) ;; *)
        if grep -q -E 'GNU (Lesser |Library |Affero )?General Public License|[^A-Za-z]L?GPL' "$doc/copyright"; then lic="$lic;(the text names the GNU GPL or LGPL)"; fi ;;
      esac
    else
      echo "warning: no copyright file for $p" >&2
      lic="(no copyright file)"
    fi
    printf '%s\t%s\t%s\t%s\t%s\n' "$p" "$v" "$s" "$sv" "$lic"
  done
} > "$out/PACKAGES.tsv"
# most copyright files refer to /usr/share/common-licenses/<name> for the full text of the GPL, LGPL,
# Apache and other licenses instead of repeating it; that folder does not exist on other systems
mkdir -p "$out/common-licenses"
cp -L /usr/share/common-licenses/* "$out/common-licenses/"

# 4. where the corresponding source is
os=$(. /etc/os-release && echo "$PRETTY_NAME")
{
  echo "Libraries bundled in the ExploitX AppImage: licenses and corresponding source"
  echo
  echo "The AppImage carries shared libraries of the system it was built on ($os): GTK, WebKitGTK and"
  echo "their dependencies, dynamically linked. Each library is used under its own license. The copyright"
  echo "and license text of each package is in copyright/<package>; PACKAGES.tsv lists every package with its"
  echo "version, its source package and the licenses its copyright file names. Where a copyright file refers"
  echo "to /usr/share/common-licenses/<name> for a license's full text, that text is in common-licenses/<name>."
  echo
  if [ -n "$sources" ]; then
    echo "Corresponding source: the source packages of every library whose copyright file names the GNU"
    echo "GPL or LGPL (\"GPL\" in the last column of PACKAGES.tsv), at the versions listed, are published next"
    echo "to this AppImage on the same release page, in the file $(basename "$sources")"
    echo "(Debian source packages: .dsc, upstream and Debian tarballs). The source of the other libraries is"
    echo "in the distribution's archive: apt-get source <source package>=<source version>."
  else
    echo "Corresponding source: the source package of each library, at the version listed, is available"
    echo "from the distribution's archive: apt-get source <source package>=<source version>."
  fi
  echo
  echo "You may replace any of these libraries with your own version: extract the AppImage"
  echo "(--appimage-extract) and replace the library under usr/lib, or run the extracted application with"
  echo "LD_LIBRARY_PATH pointing at your build."
} > "$out/README.txt"

# 5. optionally, the source packages of the LGPL/GPL-licensed libraries
if [ -n "$sources" ]; then
  work=$(mktemp -d)
  awk -F'\t' 'NR>1 && $5 ~ /GPL/ {print $3"="$4}' "$out/PACKAGES.tsv" | sort -u > "$work/list"
  ( cd "$work" && xargs -a list apt-get source --download-only -qq )
  tar -C "$work" --exclude=list -cf "$sources" .
  echo "source packages: $(wc -l < "$work/list"), $(du -h "$sources" | cut -f1)"
  rm -rf "$work"
fi

# 6. optionally, the Tauri configuration that adds every file of <out-dir> to the AppImage
if [ -n "$config" ]; then
  dir=$(cd "$out" && pwd)
  if find "$dir" -type f | grep -q '["\\]'; then echo "error: a file name in $dir needs JSON escaping" >&2; exit 1; fi
  {
    printf '{"bundle":{"linux":{"appimage":{"files":{'
    find "$dir" -type f | sort | awk -v d="$dir" -v doc="/$DOC" 'BEGIN { ORS = "" } { printf "%s\"%s/%s\":\"%s\"", (NR > 1 ? "," : ""), doc, substr($0, length(d) + 2), $0 }'
    printf '}}}}}\n'
  } > "$config"
fi
echo "packages: $(echo "$packages" | wc -w)"
