#include <string>
#include <iostream>

using namespace std;

string test_template_to_string() {
  string T_enc_sendable_string;

  for(int i=0; i<4; i++) {
    string col = "{";

    for(int j=0; j<5; j++) {
      string test = "beestje"+j;
      cout << test << endl;
      col.append(test);
      col.push_back(',');
    }

    col.push_back('}');
    T_enc_sendable_string.append(col);
  }

  cout << T_enc_sendable_string << endl;

  return T_enc_sendable_string;
}

void test_string_to_template(string temp) {

}

int main(int argc, char* argv[]) {
  string temp = test_template_to_string();
}
