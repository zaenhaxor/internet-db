<?php
$merah = "\033[31m";
$kuning = "\033[33m";
$hijau = "\033[32m";
$cyan = "\033[36m"; // biru muda
// $biru = "\033[34m";
$ungu = "\033[0;35m";
$reset = "\033[0m";
$banner = "{$hijau}
  _       _                       _          _____  ____  
 (_)     | |                     | |        |  __ \|  _ \ 
  _ _ __ | |_ ___ _ __ _ __   ___| |_ ______| |  | | |_) |
 | | '_ \| __/ _ \ '__| '_ \ / _ \ __|______| |  | |  _ < 
 | | | | | ||  __/ |  | | | |  __/ |_       | |__| | |_) |
 |_|_| |_|\__\___|_|  |_| |_|\___|\__|      |_____/|____/
 Written by Zaen {$reset}| {$kuning}Fast IP lookups for open ports and vulnerabilities{$reset}\n\n";
echo $banner;
echo "Choose mode:\n";
echo "a. {$cyan}Single IP{$reset}\n";
echo "b. {$cyan}Mass IP{$reset}\n\n";
echo "choose (a or b)?: ";
$opsi = trim(fgets(STDIN));
function ambil_data($url)
{
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $output = curl_exec($ch);
    curl_close($ch);
    return $output;
}
// single IP
if ($opsi === 'a') {
    echo "IP address: ";
    $ip = trim(fgets(STDIN));
    if (empty($ip)) {
        echo "{$merah}Empty input !{$reset}\n";
        /* referensi:
        https://stackoverflow.com/questions/6211148/how-do-i-check-if-a-users-input-is-a-valid-ip-address-or-not
        https://www.plus2net.com/php_tutorial/filter_validate_ip.php */
    } elseif (filter_var($ip, FILTER_VALIDATE_IP)) {
        $url = "https://internetdb.shodan.io/{$ip}";
        $data = ambil_data($url); // respon berupa data json
        $data = json_decode($data, true); 
        $cpes = $data['cpes']; 
        $hostnames = implode(', ', $data['hostnames']);
        $ip_address = $data['ip'];
        $ports = implode(',', $data['ports']);
        $vulns = implode(',', $data['vulns']);
        $remove_cpe = implode(', ', array_map(function ($cpe) {
            return str_replace('cpe:/a:', '', $cpe);
        }, $cpes));  
        $path = getcwd(); //https://www.php.net/manual/en/function.getcwd.php
        $output_saved = "{$path}/{$ip_address}_logs.txt";
        echo "[{$cyan}+{$reset}] {$hijau}{$ip_address}{$reset}\n";
        echo "CPE      : {$ungu}{$remove_cpe}{$reset}\n"; //CPE: Common Platform Enumeration
        echo "Hostname : {$hijau}{$hostnames}{$reset}\n";
        echo "IP       : {$cyan}{$ip_address}{$reset}\n";
        echo "Ports    : {$kuning}{$ports}{$reset}\n";
        echo "Vulns    : {$merah}{$vulns}{$reset}\n"; // output berupa kode cve, CVE: Common Vulnerabilities and Exposures
        $file = fopen($output_saved, "w");
        if ($file) {
            fwrite($file, "[+] Hasil untuk {$ip_address}\n");
            fwrite($file, "CPE      : {$remove_cpe}\n");
            fwrite($file, "Hostname : {$hostnames}\n");
            fwrite($file, "IP       : {$ip_address}\n");
            fwrite($file, "Ports    : {$ports}\n");
            fwrite($file, "Vulns    : {$vulns}\n\n");
            fclose($file);
            echo "Output: {$output_saved}\n";
        } else {
            echo "{$merah}Failed to open file !{$reset}\n";
        }
    } else {
        echo "{$merah}Invalid input !{$reset}\n";
    }
} elseif ($opsi === 'b') {
    // mass IP
    echo "File: ";
    $file_input = trim(fgets(STDIN));
    if (file_exists($file_input)) {
        $ip_file = file($file_input, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!empty($ip_file)) {
            $path = getcwd(); 
            $output_saved = "{$path}/logs_{$file_input}.txt"; 
            $file = fopen($output_saved, "w");
            if ($file) {
                foreach ($ip_file as $ips) {
                    if (filter_var($ips, FILTER_VALIDATE_IP)) {
                        $url = "https://internetdb.shodan.io/{$ips}";
                        $data = ambil_data($url);
                        $data = json_decode($data, true);
                        $ip_address = $data['ip'];
                        $cpes = $data['cpes'];
                        $hostnames = implode(', ', $data['hostnames']);
                        $ports = implode(',', $data['ports']);
                        $vulns = implode(',', $data['vulns']);
                        $remove_cpe = implode(', ', array_map(function ($cpe) {
                            return str_replace('cpe:/a:', '', $cpe);
                        }, $cpes));
                        echo "[{$cyan}+{$reset}] {$hijau}{$ip_address}{$reset}\n";
                        echo "CPE      : {$ungu}{$remove_cpe}{$reset}\n";
                        echo "Hostname : {$hijau}{$hostnames}{$reset}\n";
                        echo "IP       : {$cyan}{$ip_address}{$reset}\n";
                        echo "Ports    : {$kuning}{$ports}{$reset}\n";
                        echo "Vulns    : {$merah}{$vulns}{$reset}\n\n";
                        fwrite($file, "[+] Hasil untuk {$ip_address}\n");
                        fwrite($file, "CPE      : {$remove_cpe}\n");
                        fwrite($file, "Hostname : {$hostnames}\n");
                        fwrite($file, "IP       : {$ip_address}\n");
                        fwrite($file, "Ports    : {$ports}\n");
                        fwrite($file, "Vulns    : {$vulns}\n\n");
                    } else {
                        echo "[{$merah}-{$reset}] {$merah}Invalid IP address: $ips{$reset}\n\n";
                        fwrite($file, "Invalid IP address: $ips\n");
                    }
                }
                fclose($file);
                echo "Output: {$output_saved}\n";
            } else {
                echo "{$merah}Failed to open file !{$reset}\n";
            }
        } else {
            echo "{$merah}No valid IP address in the file.{$reset}\n";
        }
    } else {
        echo "{$merah}The specified file does not exist.{$reset}\n";
    }
} else {
    echo "{$merah}Invalid option !{$reset}\n";
}
?>
