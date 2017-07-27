package pubtkt

import (
	"github.com/mitchellh/mapstructure"
	"reflect"
	"strconv"
	"strings"
	"time"
)

func ParseTicket(ticketStr string) (*Ticket, error) {
	ticketMap := parseStringToMap(ticketStr)
	ticket := &Ticket{}
	config := mapstructure.DecoderConfig{
		DecodeHook: ticketDecoderHook,
		Result:     ticket,
	}

	decoder, err := mapstructure.NewDecoder(&config)
	if err != nil {
		return nil, err
	}
	err = decoder.Decode(ticketMap)
	if err != nil {
		return nil, err
	}
	return ticket, nil
}
func parseStringToMap(raw string) map[string]string {
	rawMap := make(map[string]string)
	elems := strings.Split(raw, ";")
	for _, elem := range elems {
		elem = strings.TrimSpace(elem)
		elemParsed := strings.Split(elem, "=")
		if len(elemParsed) == 1 {
			rawMap[elemParsed[0]] = ""
			continue
		}
		rawMap[elemParsed[0]] = strings.Join(elemParsed[1:], "=")
	}
	return rawMap
}
func ticketDecoderHook(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
	if t == reflect.TypeOf(time.Time{}) && f == reflect.TypeOf("") {
		timestamp, err := strconv.ParseInt(data.(string), 10, 64)
		if err != nil {
			return nil, err
		}
		return time.Unix(timestamp, 0), nil
	}
	if t == reflect.TypeOf([]string{}) && f == reflect.TypeOf("") {
		return strings.Split(data.(string), ","), nil
	}
	return data, nil
}
