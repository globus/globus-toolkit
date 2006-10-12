<HTML>
<HEAD>
<TITLE>Usage Reports</TITLE>
</HEAD>
<BODY>
<H3>Usage Reports:</H3>

<?php
  $PATH = ".";
  $branches = opendir($PATH);
  echo "<ul>\n";
  while($branch = readdir($branches)) {
        if ($branch  == "." || $branch == "..") {
                continue;
        }
        if (is_dir($branch)) {
		echo "<li>";
                echo "<a href=\"$branch\">$branch</a>";
                echo "</li>";
	}
  }
  closedir($branches);
  echo "</ul>\n";
?>

</BODY>
</HTML>

