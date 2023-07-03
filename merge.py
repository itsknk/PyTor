def merge_sort(arr):
	if len(arr) == 1:
		return arr

	mid = len(arr) // 2

	left = merge_sort(arr[:mid])
	right = merge_sort(arr[mid:])

	return merge(left,right)

def merge(left,right):
	output = []
	i = 0
	j = 0
	while i < len(left) and j < len(right):
		if left[i] < right[j]:
			output.append(left[i])
			i = i + 1
		else:
			output.append(right[j])
			j = j + 1

	output.extend(left[i:])
	output.extend(right[j:])

	return output

def run_merge_sort():
    unsorted_list = [4, 1, 5, 7, 2]
    print(unsorted_list)
    sorted_list = merge_sort(unsorted_list)
    print(sorted_list)

run_merge_sort()