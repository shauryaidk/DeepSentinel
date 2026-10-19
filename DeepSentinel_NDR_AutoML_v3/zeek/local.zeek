# Write all Zeek logs as one JSON object per line.
redef LogAscii::use_json = T;

# Do not write Zeek's metadata/header lines.
redef LogAscii::include_meta = F;
