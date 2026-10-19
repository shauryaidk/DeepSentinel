import torch
import torch.nn as nn
import torch.nn.functional as F

class Attention(nn.Module):
    def __init__(self, hidden_dim):
        super(Attention, self).__init__()
        self.attention = nn.Linear(hidden_dim * 2, 1)

    def forward(self, lstm_output):
        # lstm_output shape: (batch_size, sequence_len, hidden_dim * 2)
        attn_weights = F.softmax(self.attention(lstm_output), dim=1)
        context_vector = torch.sum(attn_weights * lstm_output, dim=1)
        return context_vector, attn_weights

class DGALSTM(nn.Module):
    def __init__(self, vocab_size=39, embedding_dim=32, hidden_dim=64):
        super(DGALSTM, self).__init__()
        self.embedding = nn.Embedding(vocab_size, embedding_dim, padding_idx=0)
        self.lstm = nn.LSTM(embedding_dim, hidden_dim, batch_first=True, bidirectional=True)
        
        self.attention = Attention(hidden_dim)
        self.dropout = nn.Dropout(0.3)
        
        self.fc1 = nn.Linear(hidden_dim * 2, 32)
        self.relu = nn.ReLU()
        self.fc2 = nn.Linear(32, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        embedded = self.embedding(x)
        lstm_out, _ = self.lstm(embedded)
        
        context, _ = self.attention(lstm_out)
        
        out = self.dropout(context)
        out = self.fc1(out)
        out = self.relu(out)
        out = self.fc2(out)
        return self.sigmoid(out)