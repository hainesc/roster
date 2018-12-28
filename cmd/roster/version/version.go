package version

import (
	"fmt"

	"github.com/hainesc/roster/pkg/version"
	"github.com/spf13/cobra"
)

//VersionCmd contains first-class command for version
var VersionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of Roster",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Roster version: " + version.Version)
	},
}
