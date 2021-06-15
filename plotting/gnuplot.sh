#!/bin/bash

gnuplot <<- EOF
	set xrange [*:*];
	set format x '%.6f'
	set yrange [-2:12];
	while (1){
		plot "< tail -10000 data.dat" using 1:2 with impulses title "PTP" lw 2,\
					"" using 1:3 with impulses title "UDP_6666" lw 2,\
					"" using 1:4 with impulses title "UDP_7777" lw 2,\
					"" using 1:5 with impulses title "VLAN" lw 2,\
					"" using 1:6 with impulses title "Audio" lw 2,\
					"" using 1:7 with impulses title "Video" lw 2,\
					"" using 1:8 with impulses title "OTHERS" lw 2;
		pause 2;
		replot;
	}
EOF
