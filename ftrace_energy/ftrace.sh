events=(power/cpu_frequency power/cpu_idle kgsl/kgsl_clk kgsl/kgsl_pwr_set_state
  net/net_dev_xmit net/netif_rx power/clock_set_rate)
ftrace_file=/d/tracing/trace

toggle_ftrace_event () {
  echo "$2" > /d/tracing/events/"$1"/enable
}

toggle_ftrace () {
  echo "$1" > /d/tracing/tracing_on
}

if [ "$1" = on ]; then
  for e in ${events[*]}; do
    toggle_ftrace_event "$e" 1
  done

  echo 0 > /sys/class/kgsl/kgsl-3d0/force_no_nap

  echo 96000 > /d/tracing/buffer_size_kb
  echo > $ftrace_file
  toggle_ftrace 1
elif [ "$1" = off ]; then
  toggle_ftrace 0
  cat $ftrace_file > /data/local/tmp/trace_output

  for e in ${events[*]}; do
    toggle_ftrace_event "$e" 0
  done
fi
