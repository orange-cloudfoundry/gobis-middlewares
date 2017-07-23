package utils

import (
	"reflect"
	"fmt"
)

func RequiredVal(elems...interface{}) error {
	if len(elems) % 2 == 1 {
		panic("Parameters are not in pairs")
	}
	var data interface{}
	for i, elem := range elems {
		if (i + 1) % 2 == 1 {
			data = elem
			continue
		}
		err := requiredVal(data, fmt.Sprint(elem))
		if err != nil {
			return err
		}
	}
	return nil
}
func requiredVal(data interface{}, paramsName string) error {
	if !elemIsEmpty(data) {
		return nil
	}
	return fmt.Errorf("%s cannot be empty.", paramsName)
}

func CondVal(data, value interface{}) interface{} {
	if !elemIsEmpty(data) {
		return data
	}
	finalData := reflect.New(reflect.TypeOf(data))
	finalData.Elem().Set(reflect.ValueOf(value))
	return finalData.Elem().Interface()
}

func elemIsEmpty(data interface{}) bool {
	typeData := reflect.TypeOf(data)
	valueData := reflect.ValueOf(data)
	if typeData.Kind() == reflect.Ptr {
		typeData = typeData.Elem()
		valueData = valueData.Elem()
	}
	if typeData.Kind() == reflect.Slice || typeData.Kind() == reflect.Map {
		return valueData.Len() == 0
	}
	zeroVal := reflect.Zero(typeData)
	if zeroVal.Interface() == valueData.Interface() {
		return true
	}
	return false
}