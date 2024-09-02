import os
import openai
import json


openai.api_key = ''


code_base_path = "D:\\repo\\codetest\\code"


system_prompt = """
You are a cybersecurity specialist mastering vulnerability discovery. Answer as concisely as possible.
Ensure all explanations are detailed and step-by-step, using precise terminology.
"""




def analyze_vulnerability(code_snippet):
    user_prompt = f"""
    Please review and analyze the following code. Determine whether it is vulnerable. If vulnerabilities are found, identify each type of vulnerability and provide a step-by-step explanation of why it is vulnerable. Then, provide a detailed step-by-step guide to fix each issue.
    Additionally, provide a summary that includes the total number of vulnerabilities found and their respective types.

    Answer in the following format:
    VULNERABLE: YES/NO/NOT SURE
    SUMMARY: <Total number of vulnerabilities found: X>
    TYPE: <Type of Vulnerability 1>
    EXPLANATION: <Detailed Explanation>
    FIX: <Step-by-step Fix>

    TYPE: <Type of Vulnerability 2>
    EXPLANATION: <Detailed Explanation>
    FIX: <Step-by-step Fix>

    ... (Repeat TYPE, EXPLANATION, and FIX sections for each vulnerability)

    Code:
    {code_snippet}

    """

    print(f"Checking for vulnerabilities...")
    response = openai.ChatCompletion.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        max_tokens=3000,
        temperature=0.5,
        top_p=0.5

    result = response['choices'][0]['message']['content'].strip()
    return result



def scan_files(file_paths):
    results = {'vulnerable': 0, 'not_vulnerable': 0, 'details': {}}
    summary_results = {}
    total_vulnerabilities = 0

    for file_path in file_paths:
        print(f"Scanning file: {file_path}")
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                code_snippet = file.read()
        except UnicodeDecodeError:
            print(f"Skipping file due to encoding issues: {file_path}")
            continue

        result = analyze_vulnerability(code_snippet)
        if 'VULNERABLE: YES' in result:
            results['vulnerable'] += 1


            summary_line = next((line for line in result.split('\n') if 'SUMMARY:' in line), None)
            if summary_line:
                num_vulnerabilities = int(summary_line.split('Total number of vulnerabilities found: ')[1])
                total_vulnerabilities += num_vulnerabilities


            vulnerabilities = result.split('TYPE: ')[1:]
            vuln_types = []
            for vulnerability in vulnerabilities:
                vuln_type = vulnerability.split('\n')[0].strip()
                vuln_types.append(vuln_type)

                if file_path not in results['details']:
                    results['details'][file_path] = {
                        'total_vulnerabilities': 0,
                        'vulnerabilities': []
                    }
                results['details'][file_path]['total_vulnerabilities'] += 1
                results['details'][file_path]['vulnerabilities'].append({
                    'vulnerability': vulnerability.strip(),
                })

            summary_results[file_path] = {
                'total_vulnerabilities': num_vulnerabilities,
                'vulnerability_types': vuln_types
            }

        else:
            results['not_vulnerable'] += 1

    return results, total_vulnerabilities, summary_results



def get_all_files(base_path):
    print(f"Fetching all files from directory: {base_path}")
    file_paths = []
    for root, dirs, files in os.walk(base_path):
        for file in files:
            if file.endswith(('.c', '.cpp', '.js', '.java', '.py', '.cs', '.php')):
                file_paths.append(os.path.join(root, file))
    return file_paths



file_paths = get_all_files(code_base_path)
print(f"Total files to scan: {len(file_paths)}")

vulnerability_results, total_vulnerabilities, summary_results = scan_files(file_paths)


detailed_output_file = "detailed_vulnerability_results.json"
detailed_report = {
    'total_vulnerabilities': total_vulnerabilities,
    'vulnerability_results': vulnerability_results,
}
with open(detailed_output_file, 'w') as json_file:
    json.dump(detailed_report, json_file, indent=4)

print(f"Detailed results saved to {detailed_output_file}")


summary_output_file = "summary_vulnerability_results.json"
with open(summary_output_file, 'w') as json_file:
    json.dump(summary_results, json_file, indent=4)

print(f"Summary results saved to {summary_output_file}")
