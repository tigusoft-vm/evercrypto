#!/bin/bash
# practical testing geport alghoritm implementation

app="$1"
dir="$2"
verbose=false

check() {
  for i in "$1"/*; do
    if [[ ! -d $i && ($i != "sig") && ($i != "$dir/sig") && ($i != "$1/sig") && ($i != "$1/*") && ($(wc -c <"$i") -lt 4000000000) ]]; then
	if [[ $verbose == true ]]; then
          echo "testing $i"
        fi

      touch ./priv ./pub ./sig
      $app -g ./priv ./pub --yes &> /dev/null
      $app -s "$i" ./priv ./sig --yes
      is_ok=$($app -c "$i" ./sig ./pub)
      if [[ $is_ok != "signature is OK" ]]; then
        echo "something wrong with "$i" file"
        exit 2
      fi
    
      is_ok=$($app -v ./priv ./pub)
      if [[ $is_ok != "public key is OK" ]]; then
        echo "something wrong with public key atfer signing "$i" file"
        exit 3
      fi
    else
      [ "$(ls -A "$i")" ] && check "$i"
    fi
  done
}




# -------------------------- starting here
if [[ ($# -gt 0) && ($1 == "--help") ]]; then
  echo "This script is designed to check correctness of geport digital signature implementation. Usage:"
  echo "$ bash ./script ./geport_implementation_app ./path_to_files"
  echo "Script will recursively sign all files in given path and check if signature is correct."
  echo "If any error appear, script will stop work and give you appropriate information."
  echo "In this case, please contact author giving script error output, ./sig ./priv ./pub files and checked file (or just sha512 sum of this file)."
  echo "--verbose at the end of command to verbose mode"
  exit 0
fi

if [[ ! $EUID != 0 ]]; then
  echo "This script should NOT be run as root" 1>&2
  exit 1
fi

if [[ $# -lt 2 ]]; then
  echo "Use --help to show manual"
  exit 4
fi

if [[ ($# -gt 2) && ($3 == "--verbose") ]]; then
  verbose=true
else
  echo "tests started..."
fi



check $dir

echo "OK"
rm ./pub ./priv ./sig

exit 0
