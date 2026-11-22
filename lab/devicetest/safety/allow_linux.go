package safety

import "regexp"

func reads() map[string]readShape {
	return map[string]readShape{
		"ip": {ipPath(), regexp.MustCompile(`^(-[46] )?(-o )?(route|addr|link)( show)?( table all)?$`)},
	}
}
