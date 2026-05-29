package apache

import "testing"

func TestAttributeConfigtestError(t *testing.T) {
	ourFile := "/etc/apache2/sites-available/nurproxy-app.example.com.conf"
	tests := []struct {
		name        string
		out         string
		ourFile     string
		wantLocated bool
		wantOurs    bool
		wantFile    string
		wantLine    int
	}{
		{
			name:        "ah00526_blames_operator",
			out:         "AH00526: Syntax error on line 5 of /etc/apache2/sites-enabled/operator.conf:\nInvalid command 'Bogus', perhaps misspelled or defined by a module not included in the server configuration",
			ourFile:     ourFile,
			wantLocated: true,
			wantOurs:    false,
			wantFile:    "/etc/apache2/sites-enabled/operator.conf",
			wantLine:    5,
		},
		{
			name:        "blames_our_file_by_basename_symlink",
			out:         "Syntax error on line 12 of /etc/apache2/sites-enabled/nurproxy-app.example.com.conf:",
			ourFile:     ourFile,
			wantLocated: true,
			wantOurs:    true,
			wantFile:    "/etc/apache2/sites-enabled/nurproxy-app.example.com.conf",
			wantLine:    12,
		},
		{
			name:        "rhel_confd_path",
			out:         "Syntax error on line 3 of /etc/httpd/conf.d/nurproxy-app.example.com.conf:\nbad",
			ourFile:     "/etc/httpd/conf.d/nurproxy-app.example.com.conf",
			wantLocated: true,
			wantOurs:    true,
			wantFile:    "/etc/httpd/conf.d/nurproxy-app.example.com.conf",
			wantLine:    3,
		},
		{
			name:        "no_location_unattributed",
			out:         "httpd: could not open error log file /var/log/httpd/error_log. Permission denied",
			ourFile:     ourFile,
			wantLocated: false,
		},
		{
			name:        "empty_output",
			out:         "",
			ourFile:     ourFile,
			wantLocated: false,
		},
		{
			name:        "last_location_wins",
			out:         "Syntax error on line 1 of /etc/apache2/apache2.conf:\nincluded from line 2\nSyntax error on line 7 of /etc/apache2/sites-enabled/operator.conf:",
			ourFile:     ourFile,
			wantLocated: true,
			wantOurs:    false,
			wantFile:    "/etc/apache2/sites-enabled/operator.conf",
			wantLine:    7,
		},
		{
			name:        "empty_ourfile_never_ours",
			out:         "Syntax error on line 4 of /etc/apache2/sites-enabled/nurproxy-app.example.com.conf:",
			ourFile:     "",
			wantLocated: true,
			wantOurs:    false,
			wantFile:    "/etc/apache2/sites-enabled/nurproxy-app.example.com.conf",
			wantLine:    4,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := AttributeConfigtestError(tt.out, tt.ourFile)
			if a.Located != tt.wantLocated {
				t.Fatalf("Located = %v, want %v (raw=%q)", a.Located, tt.wantLocated, a.Raw)
			}
			if !tt.wantLocated {
				return
			}
			if a.Ours != tt.wantOurs {
				t.Errorf("Ours = %v, want %v", a.Ours, tt.wantOurs)
			}
			if a.File != tt.wantFile {
				t.Errorf("File = %q, want %q", a.File, tt.wantFile)
			}
			if a.Line != tt.wantLine {
				t.Errorf("Line = %d, want %d", a.Line, tt.wantLine)
			}
			if a.Raw != tt.out {
				t.Errorf("Raw not preserved")
			}
		})
	}
}
