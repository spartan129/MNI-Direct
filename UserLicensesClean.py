import csv

input_file = 'UserLicenses.csv'
output_file = 'UserLicensesCleaned.csv'

with open(input_file, 'r') as infile, open(output_file, 'w', newline='') as outfile:
    reader = csv.DictReader(infile)
    fieldnames = reader.fieldnames
    writer = csv.DictWriter(outfile, fieldnames=fieldnames)
    writer.writeheader()  # write header
    
    for row in reader:
        if 'McCorkleNurseries.com' not in row['UserEmail']:
            writer.writerow(row)

print(f"Filtered data saved to {output_file}")
