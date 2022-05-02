from ast import Pass
from xml.dom.pulldom import PROCESSING_INSTRUCTION


ticket = {'A-B':100, 'B-C':100, 'A-C':200} #価格設定
sum=10
print('\n',sum)

for i in range(3,0,-1):
    if sum<=9:
        print('1000円札の受付を停止します。')

    x = input('お金を入れてください。\n') #投入金額入力
    if sum<=9:
        if int(x)>=1000:
            print('お釣りがありません。')
            continue
            

    if int(x)<=900:
        sum=sum+(int(x)/100)
        print('\n',sum)


    if False == x.isdigit(): #金額が入力されなかったら
        print('金額を入力してください。')
            
    else: #それ以外(金額が入力されたら)
        print('\n',ticket) #切符の一覧を表示
            
        select=input('購入する切符を選んでください。\n')

        try:
            z = ticket[select] #選択した切符の価格格納
                
        except(KeyError): #リストにないものが入力されたら
            print('%s はありません。' %select)
            
        else: #それ以外(リストにあるものが選択されたら)
            y = int(int(x) - z) #お釣り計算
            sum = sum - ( y / 100 )
            print('\n',sum)
            if y > 0: #お釣りがプラスなら
                print('\n%s を選択しました。 お釣りは %d 円です。' % (select, y)) #お釣り出力

            elif y == 0:
                print('ありがとうございました。')
            else: #それ以外(お釣りがマイナス)
                print('金額が不足しています。')
            if i==1:
                print('切符を補充してください。\n')               